import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import PurePosixPath
from urllib.parse import unquote


FUNCTION = (ast.FunctionDef, ast.AsyncFunctionDef)
BRANCH = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.With, ast.AsyncWith, ast.Match)
METHODS = {name: name.upper() for name in ('get', 'post', 'put', 'patch', 'delete')}
FRAMEWORK = {'flask.Flask', 'flask.Blueprint'}
BEFORE_HOOKS = {'before_request', 'before_app_request'}
AFTER_HOOKS = {'after_request', 'after_app_request'}
HOOKS = BEFORE_HOOKS | AFTER_HOOKS
APP_HOOKS = {'before_app_request', 'after_app_request'}
REGISTRATIONS = {'route', 'add_url_rule', 'register_blueprint'} | METHODS.keys() | HOOKS
VARIABLE = re.compile(r'([^<>]*)<(?:(string|default|int|float|uuid|path):)?([A-Za-z_][A-Za-z_0-9]*)>([^<>]*)')
UUID = re.compile(r'[\da-fA-F]{8}(?:-[\da-fA-F]{4}){3}-[\da-fA-F]{12}', re.ASCII)


def literal(node):
    return node.value if isinstance(node, ast.Constant) else None


def option(call, name):
    return next((kw.value for kw in call.keywords if kw.arg == name), None)


def argument(call, index, name):
    return call.args[index] if len(call.args) > index else option(call, name)


def name_targets(node):
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            yield from name_targets(item)
    elif isinstance(node, ast.Starred):
        yield from name_targets(node.value)


def assigned_names(node):
    if isinstance(node, ast.Assign):
        return [name for target in node.targets for name in name_targets(target)]
    if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        return list(name_targets(node.target))
    return []


def updated_targets(node):
    if isinstance(node, ast.Assign):
        return node.targets
    if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        return [node.target]
    return []


def walk_body(body):
    pending = [(node, False) for node in reversed(body)]
    while pending:
        node, conditional = pending.pop()
        yield node, conditional
        if not isinstance(node, FUNCTION + (ast.ClassDef, ast.Lambda)):
            nested = conditional or isinstance(node, BRANCH)
            pending.extend((child, nested) for child in reversed(list(ast.iter_child_nodes(node))))


def join_paths(prefix, path):
    if not prefix or not path:
        return prefix or path
    return prefix.rstrip('/') + '/' + path.lstrip('/')


def route_pattern(value):
    if not isinstance(value, str) or len(value) > 2048 or (value and not value.startswith('/')) or any(
            char.isspace() or ord(char) < 32 or char in '?#\\\x7f' for char in value):
        return None
    parts = []
    parameters = {}
    for part in value.split('/')[1:]:
        if '<' not in part and '>' not in part:
            parts.append(part)
            continue
        variable = VARIABLE.fullmatch(part)
        if not variable:
            return None
        before, converter, name, after = variable.groups()
        converter = 'string' if converter in {None, 'default'} else converter
        if name in parameters or (converter == 'path' and converter in parameters.values()):
            return None
        parameters[name] = converter
        parts.append((before, converter, after))
    return parts, parameters


def matches_path(pattern, segments):
    parts, parameters = pattern
    extra = len(segments) - len(parts)
    if extra < 0 or (extra and 'path' not in parameters.values()):
        return False
    uncertain = False
    index = 0
    for part in parts:
        if isinstance(part, str):
            if part != segments[index]:
                return False
            index += 1
            continue
        before, converter, after = part
        width = extra + 1 if converter == 'path' else 1
        piece = '/'.join(segments[index:index + width])
        index += width
        if len(piece) <= len(before) + len(after) or not piece.startswith(before) or not piece.endswith(after):
            return False
        value = piece[len(before):len(piece) - len(after)]
        if converter == 'path' and value.startswith('/'):
            return False
        if converter == 'uuid' and not UUID.fullmatch(value):
            return False
        if converter in {'int', 'float'}:
            numeric = r'\d+' if converter == 'int' else r'\d+\.\d+'
            if not re.fullmatch(numeric, value):
                return False
            # Werkzeug releases differ on non-ASCII decimal digits.
            uncertain = uncertain or not value.isascii()
    return None if uncertain else True


def location(file, node):
    return {'file_path': file, 'line': node.lineno}


class Scope:
    def __init__(self, file, module, package, label, body, parent=None):
        self.file = file
        self.module = module
        self.package = package
        self.label = label
        self.body = body
        self.parent = parent
        self.bindings = {}
        self.imports = set()
        self.dependency_imports = set()
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.add_import(node)
            elif isinstance(node, FUNCTION + (ast.ClassDef,)):
                self.bind(node.name, self.local(node.name))
            else:
                for name in assigned_names(node):
                    self.bind(name, self.local(name))
            for child in ast.walk(node):
                if child is not node and isinstance(child, (ast.Import, ast.ImportFrom)):
                    self.add_import(child, nested=True)
        self.dependency_imports.update(self.imports)

    def local(self, name):
        return self.label + '.' + name

    def bind(self, name, target):
        self.bindings[name] = None if name in self.bindings else target

    def add_import(self, node, *, nested=False):
        imports = self.dependency_imports if nested else self.imports
        if isinstance(node, ast.Import):
            for item in node.names:
                imports.add(item.name)
                first = item.name.split('.')[0]
                if not nested:
                    self.bind(item.asname or first, item.name if item.asname else first)
            return
        prefix = []
        if node.level:
            package_parts = self.package.split('.') if self.package else []
            if node.level > len(package_parts):
                return
            prefix = package_parts[:len(package_parts) - node.level + 1]
        if node.module:
            prefix.append(node.module)
        if prefix:
            imports.add('.'.join(prefix))
        for item in node.names:
            if item.name != '*':
                target = '.'.join([*prefix, item.name])
                imports.add(target)
                if not nested:
                    self.bind(item.asname or item.name, target)

    def resolve(self, node):
        if isinstance(node, ast.Name):
            if node.id in self.bindings:
                return self.bindings[node.id]
            return self.parent.resolve(node) if self.parent else None
        if isinstance(node, ast.Attribute):
            owner = self.resolve(node.value)
            return owner + '.' + node.attr if owner else None
        return None

    def where(self, node):
        return location(self.file, node)


def load_modules(files):
    scopes = {}
    review = []
    modules = set()
    for file in files:
        name = file['file_path']
        parts = list(PurePosixPath(file.get('module_path', name)).with_suffix('').parts)
        is_package = parts[-1] == '__init__' and len(parts) > 1
        if is_package:
            parts.pop()
        module = '.'.join(parts)
        if any(not part.isidentifier() for part in parts) or module in modules:
            review.append({'reason': 'module_path_unresolved', 'source': {'file_path': name, 'line': 1}})
            continue
        modules.add(module)
        try:
            source = file['source']
            if source is None:
                raise ValueError('expected UTF-8 source')
            tree = ast.parse(source.removeprefix('\ufeff'), filename=name)
        except (SyntaxError, ValueError, RecursionError) as error:
            review.append({'reason': 'source_parse_error', 'module': module,
                           'source': {'file_path': name, 'line': getattr(error, 'lineno', 1) or 1}})
            continue
        package = module if is_package else module.rpartition('.')[0]
        scopes[name] = Scope(name, module, package, module, tree.body)
    return scopes, review


def definitions(scopes):
    objects = {}
    functions = {}
    for scope in scopes:
        for node in scope.body:
            if isinstance(node, FUNCTION) and scope.bindings.get(node.name) == scope.local(node.name):
                functions[scope.local(node.name)] = (node, scope)
            names = assigned_names(node)
            if len(names) != 1 or scope.bindings.get(names[0]) != scope.local(names[0]):
                continue
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                continue
            call = node.value
            kind = scope.resolve(call.func)
            if kind in FRAMEWORK:
                objects[scope.local(names[0])] = {
                    'kind': kind, 'definition': scope.where(node), 'prefix': option(call, 'url_prefix'),
                    'dynamic_scope': any(kw.arg in {None, 'subdomain', 'host_matching'} for kw in call.keywords),
                    'strict_slashes': True, 'automatic_options': True,
                    'routes': [], 'hooks': [], 'mounts': [], 'review': [],
                }
    return objects, functions


def imported_scopes(modules, entry, factory, *, nested=False):
    pending = [entry] if factory is None else [entry, factory]
    seen = set()
    reachable = []
    while pending:
        scope = pending.pop()
        if scope in seen:
            continue
        seen.add(scope)
        reachable.append(scope)
        imports = scope.dependency_imports if nested else scope.imports
        for module in reversed(modules):
            if any(name == module.module or name.startswith(module.module + '.') for name in imports):
                pending.append(module)
    return reachable


def on_object(objects, scope, target):
    if not isinstance(target, ast.Attribute):
        return None, None
    return objects.get(scope.resolve(target.value)), target.attr


def changed_converter_map(objects, scope, target):
    if isinstance(target, ast.Subscript):
        target = target.value
    if isinstance(target, ast.Attribute) and target.attr == 'converters' and isinstance(target.value, ast.Attribute):
        owner, name = on_object(objects, scope, target.value)
        return owner if name == 'url_map' else None
    return None


def methods_for(call, operation):
    explicit = option(call, 'methods')
    if operation in METHODS:
        return {METHODS[operation]} if explicit is None else None
    if explicit is None:
        return {'GET'}
    if isinstance(explicit, (ast.List, ast.Tuple, ast.Set)):
        methods = [literal(item) for item in explicit.elts]
        if methods and all(isinstance(method, str) and method for method in methods):
            return {method.upper() for method in methods}
    return None


def note(entity, reason, scope, node):
    entity['review'].append({'reason': reason, 'source': scope.where(node)})


def route_declaration(entity, scope, call, operation, handler):
    path = literal(argument(call, 0, 'rule'))
    methods = methods_for(call, operation)
    slash_node = option(call, 'strict_slashes')
    options_node = option(call, 'provide_automatic_options')
    strict_slashes = literal(slash_node)
    automatic_options = literal(options_node)
    dynamic = any(kw.arg in {None, 'subdomain', 'host'} for kw in call.keywords)
    dynamic = dynamic or any(node is not None and not isinstance(node, ast.Constant)
                             for node in [slash_node, options_node])
    dynamic = dynamic or any(value is not None and type(value) is not bool for value in [strict_slashes, automatic_options])
    if not handler or route_pattern(path) is None or not methods or dynamic:
        note(entity, 'route_requires_review', scope, call)
        return
    if entity['kind'] == 'flask.Flask':
        if strict_slashes is None:
            strict_slashes = entity['strict_slashes']
        if automatic_options is None and not entity['automatic_options']:
            automatic_options = False
    entity['routes'].append({'path': path, 'methods': methods, 'handler': handler, 'source': scope.where(call),
                             'strict_slashes': strict_slashes, 'automatic_options': automatic_options})


def register_hook(entity, scope, node, operation, handler):
    if operation in APP_HOOKS and entity['kind'] != 'flask.Blueprint':
        note(entity, 'hook_requires_review', scope, node)
    elif handler is None and operation in BEFORE_HOOKS:
        note(entity, 'hook_requires_review', scope, node)
    else:
        entity['hooks'].append((operation, handler, scope.where(node)))


def register_call(objects, functions, scope, call):
    if isinstance(call.func, ast.Attribute):
        changed = changed_converter_map(objects, scope, call.func.value)
        if changed:
            note(changed, 'route_converter_requires_review', scope, call)
    entity, operation = on_object(objects, scope, call.func)
    if not entity:
        return
    if operation == 'register_blueprint':
        child_key = scope.resolve(argument(call, 0, 'blueprint'))
        child = objects.get(child_key)
        explicit = option(call, 'url_prefix')
        prefix = child['prefix'] if child and (explicit is None or isinstance(explicit, ast.Constant) and explicit.value is None) else explicit
        path = '' if prefix is None or isinstance(prefix, ast.Constant) and prefix.value is None else literal(prefix)
        if (not child or child['kind'] != 'flask.Blueprint' or route_pattern(path) is None or child['dynamic_scope']
                or any(kw.arg in {None, 'subdomain'} for kw in call.keywords)):
            note(entity, 'mount_requires_review', scope, call)
        else:
            entity['mounts'].append((child_key, path, scope.where(call)))
    elif operation == 'add_url_rule':
        route_declaration(entity, scope, call, operation, functions.get(scope.resolve(argument(call, 2, 'view_func'))))
    elif operation in HOOKS:
        handler = functions.get(scope.resolve(argument(call, 0, 'f')))
        register_hook(entity, scope, call, operation, handler)
    elif operation == 'register_error_handler':
        note(entity, 'response_processing_requires_review', scope, call)


def register_decorators(objects, functions, scope, node):
    handler = functions.get(scope.local(node.name))
    for item in node.decorator_list:
        target = item.func if isinstance(item, ast.Call) else item
        entity, operation = on_object(objects, scope, target)
        if not entity:
            continue
        if operation in METHODS.keys() | {'route'} and isinstance(item, ast.Call):
            route_declaration(entity, scope, item, operation, handler)
        elif operation in HOOKS:
            register_hook(entity, scope, item, operation, None if isinstance(item, ast.Call) else handler)
        elif operation in {'errorhandler', 'app_errorhandler'}:
            note(entity, 'response_processing_requires_review', scope, item)


def routing_default(objects, scope, node, target, conditional=False):
    owner = None
    field = None
    if isinstance(target, ast.Attribute) and target.attr == 'strict_slashes':
        owner, operation = on_object(objects, scope, target.value)
        if operation == 'url_map':
            field = 'strict_slashes'
    elif isinstance(target, ast.Subscript) and literal(target.slice) == 'PROVIDE_AUTOMATIC_OPTIONS':
        owner, operation = on_object(objects, scope, target.value)
        if operation == 'config':
            field = 'automatic_options'
    if owner is None or owner['kind'] != 'flask.Flask' or field is None:
        return
    value = literal(node.value) if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
    if not conditional and type(value) is bool:
        owner[field] = value
    else:
        note(owner, 'routing_default_requires_review', scope, target)


def collect_registrations(scopes, objects, functions):
    for scope in scopes:
        for statement in scope.body:
            if isinstance(statement, FUNCTION):
                register_decorators(objects, functions, scope, statement)
            elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
                register_call(objects, functions, scope, statement.value)
            elif isinstance(statement, BRANCH):
                for node, _ in walk_body([statement]):
                    for name in assigned_names(node):
                        entity = objects.get(scope.bindings.get(name))
                        if entity:
                            note(entity, 'conditional_rebinding', scope, node)
                    for target in updated_targets(node):
                        routing_default(objects, scope, node, target, conditional=True)
                        changed = changed_converter_map(objects, scope, target)
                        if changed:
                            note(changed, 'route_converter_requires_review', scope, target)
                    targets = [node.func] if isinstance(node, ast.Call) else []
                    if isinstance(node, FUNCTION):
                        targets = [item.func if isinstance(item, ast.Call) else item for item in node.decorator_list]
                    for target in targets:
                        entity, operation = on_object(objects, scope, target)
                        if entity and operation in REGISTRATIONS:
                            note(entity, 'conditional_registration', scope, target)
            else:
                for target in updated_targets(statement):
                    routing_default(objects, scope, statement, target)
                    changed = changed_converter_map(objects, scope, target)
                    if changed:
                        note(changed, 'route_converter_requires_review', scope, target)
                    entity, operation = on_object(objects, scope, target)
                    if entity and operation == 'wsgi_app':
                        note(entity, 'wsgi_middleware_requires_review', scope, target)


def function_details(item, registration=None, *, response_hook=False):
    node, scope = item
    local = Scope(scope.file, scope.module, scope.package, scope.local(node.name), node.body, scope)
    for value in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs, node.args.vararg, node.args.kwarg]:
        if value is not None:
            local.bind(value.arg, local.local(value.arg))
    sites = []
    for child, conditional in walk_body(node.body):
        kind = 'return'
        result = child.value if isinstance(child, ast.Return) else None
        code = None
        implicit = False
        if not response_hook and isinstance(result, ast.Tuple) and len(result.elts) in {2, 3}:
            code = literal(result.elts[1])
        elif isinstance(result, ast.Call):
            name = local.resolve(result.func)
            if name in {'flask.Response', 'werkzeug.wrappers.Response'}:
                status = argument(result, 1, 'status')
                code = literal(status)
                if (status is None or isinstance(status, ast.Constant) and status.value is None) and not (
                    any(keyword.arg is None for keyword in result.keywords) or any(isinstance(arg, ast.Starred) for arg in result.args)
                ):
                    code, implicit = 200, True
            elif name == 'flask.make_response':
                code = literal(argument(result, 1, 'status'))
            elif name in {'flask.redirect', 'werkzeug.utils.redirect'}:
                value = argument(result, 1, 'code')
                if value is not None:
                    code = literal(value)
                elif not any(k.arg is None for k in result.keywords) and not any(isinstance(a, ast.Starred) for a in result.args):
                    code, implicit = 302, True
            elif name == 'flask.jsonify':
                code, implicit = 200, True
        elif not response_hook and isinstance(result, ast.Constant) and isinstance(result.value, (str, bytes)):
            code, implicit = 200, True
        elif not response_hook and isinstance(result, (ast.Dict, ast.List)):
            code, implicit = 200, True
        elif not response_hook and isinstance(child, ast.Call) and local.resolve(child.func) == 'flask.abort':
            code = literal(argument(child, 0, 'code'))
            kind = 'abort'
        if type(code) is int and 100 <= code <= 599:
            site = {'kind': kind, 'status_code': code, 'conditional': conditional, 'source': scope.where(child)}
            if implicit:
                site['implicit'] = True
            sites.append(site)
    decorators = []
    for item in node.decorator_list:
        target = item.func if isinstance(item, ast.Call) else item
        if isinstance(target, ast.Attribute) and target.attr in REGISTRATIONS:
            continue
        name = scope.resolve(target)
        decorators.append({'name': name, 'source': scope.where(item)})
    report = {'name': node.name, 'definition': scope.where(node), 'decorators': decorators[:8],
              'status_sites': sites[:12], 'status_site_count': len(sites)}
    if registration is not None:
        report['registration'] = registration
    return report


def match_route(objects, app_key, request, decoded_path, review):
    pending = [(app_key, '', [], ())]
    found = []
    redirects = []
    app_hooks = {}
    checked = 0
    request_segments = decoded_path.split('/')[1:]
    method = request['method']
    app = objects[app_key]
    while pending and checked < 256:
        key, prefix, mounts, ancestors = pending.pop()
        checked += 1
        entity = objects[key]
        if key in ancestors:
            review.append({'reason': 'mount_cycle', 'source': mounts[-1]['registration']})
            continue
        review.extend(entity['review'])
        for hook, function, registration in entity['hooks']:
            if key == app_key or hook in APP_HOOKS:
                dedup = (registration['file_path'], registration['line'])
                app_hooks.setdefault(dedup, (hook, function, registration))
        for route in entity['routes']:
            methods = route['methods']
            automatic_head = method == 'HEAD' and 'GET' in methods and 'HEAD' not in methods
            automatic_options = route['automatic_options']
            if automatic_options is None:
                automatic_options = app['automatic_options'] and 'OPTIONS' not in methods
            if method not in methods and not automatic_head and not (method == 'OPTIONS' and automatic_options):
                continue
            rule = join_paths(prefix, route['path'])
            pattern = route_pattern(rule)
            matched = matches_path(pattern, request_segments) if pattern is not None else None
            framework = None
            strict = app['strict_slashes'] if route['strict_slashes'] is None else route['strict_slashes']
            if matched is False and not strict and decoded_path != '/':
                alternate = decoded_path[:-1] if decoded_path.endswith('/') else decoded_path + '/'
                matched = matches_path(pattern, alternate.split('/')[1:])
            elif matched is False and rule.endswith('/') and not decoded_path.endswith('/'):
                matched = matches_path(pattern, [*request_segments, ''])
                if matched:
                    framework = {'kind': 'strict_slash_redirect', 'status_code': 308, 'location_path': request['path'] + '/'}
            if matched is None:
                review.append({'reason': 'route_converter_requires_review', 'source': route['source']})
            elif matched:
                if framework is None and method == 'OPTIONS' and automatic_options:
                    allowed = methods | {'OPTIONS'} | ({'HEAD'} if 'GET' in methods else set())
                    framework = {'kind': 'automatic_options', 'status_code': 200, 'allowed_methods': sorted(allowed)}
                elif framework is None and automatic_head:
                    framework = {'kind': 'automatic_head', 'body_expected': False}
                item = (route, rule, pattern[1], mounts, (*ancestors, key), framework)
                (redirects if framework and framework['kind'] == 'strict_slash_redirect' else found).append(item)
        for child, child_prefix, site in reversed(entity['mounts']):
            full_prefix = join_paths(prefix, child_prefix)
            mount = {'prefix': full_prefix, 'registration': site, 'blueprint': objects[child]['definition']}
            pending.append((child, full_prefix, [*mounts, mount], (*ancestors, key)))
    if pending:
        review.append({'reason': 'mount_limit', 'source': objects[app_key]['definition']})
    return found or redirects, list(app_hooks.values())


def hook_details(item):
    level, hook, function, registration = item
    details = {'scope': level, 'hook': hook}
    if function is None:
        return {**details, 'registration': registration, 'resolved': False, 'status_sites': [], 'status_site_count': 0}
    return {**details, **function_details(function, registration, response_hook=hook in AFTER_HOOKS)}


def trace(data):
    scopes, review = load_modules(data['files'])
    entry_file = data['files'][0]['file_path']
    entry_scope = scopes.get(entry_file)
    if not entry_scope:
        return {'status': 'incomplete', 'match_count': 0, 'review': review}
    all_scopes = list(scopes.values())
    objects, functions = definitions(all_scopes)
    app_key = entry_scope.bindings.get(data['entrypoint'])
    entry = None
    factory = functions.get(app_key)
    factory_scope = None
    if factory:
        node, scope = factory
        entry = scope.where(node)
        body = node.body
        returns = [child for child, _ in walk_body(body) if isinstance(child, ast.Return)]
        if len(returns) != 1 or returns[0] is not body[-1] or not isinstance(node, ast.FunctionDef) or node.decorator_list:
            app_key = None
        else:
            factory_scope = Scope(scope.file, scope.module, scope.package, app_key, body, scope)
            local_objects, local_functions = definitions([factory_scope])
            objects.update(local_objects)
            functions.update(local_functions)
            app_key = factory_scope.resolve(returns[0].value)
    if app_key not in objects or objects[app_key]['kind'] != 'flask.Flask':
        review.append({'reason': 'entrypoint_unresolved', 'source': entry or {'file_path': entry_file, 'line': 1}})
        return {'status': 'incomplete', 'entry': entry, 'match_count': 0, 'review': review}
    entry = entry or objects[app_key]['definition']
    request_path = data['request']['path']
    try:
        if re.search(r'%(?![0-9a-fA-F]{2})', request_path):
            raise ValueError('invalid percent encoding')
        decoded_path = unquote(request_path, errors='strict')
        if any(ord(char) < 32 or ord(char) == 127 for char in decoded_path):
            raise ValueError('invalid decoded path')
    except (UnicodeError, ValueError):
        return {'status': 'incomplete', 'entry': entry, 'match_count': 0,
                'review': [{'reason': 'invalid_request_path_encoding', 'source': entry}]}
    if objects[app_key]['dynamic_scope']:
        review.append({'reason': 'application_scope_requires_review', 'source': entry})
    reachable = imported_scopes(all_scopes, entry_scope, factory_scope)
    dependencies = imported_scopes(all_scopes, entry_scope, factory_scope, nested=True) if review else []
    imported = {name for scope in dependencies for name in scope.dependency_imports}
    unrelated = [issue for issue in review if issue['reason'] == 'source_parse_error'
                 and not any(name == issue['module'] or name.startswith(issue['module'] + '.') for name in imported)]
    review = [issue for issue in review if issue not in unrelated]
    collect_registrations(reachable, objects, functions)
    found, app_hooks = match_route(objects, app_key, data['request'], decoded_path, review)
    if len(found) > 1 and all(item[-1] and item[-1]['kind'] == 'automatic_options' and item[1] == found[0][1] for item in found):
        combined = sorted({method for item in found for method in item[-1]['allowed_methods']})
        found[0][-1]['allowed_methods'] = combined
        found = found[:1]
    hook_items = [('app', *hook) for hook in app_hooks]
    if len(found) == 1:
        route, rule, parameters, mounts, chain, framework = found[0]
        for key in chain[1:]:
            hook_items.extend(('blueprint', *hook) for hook in objects[key]['hooks'] if hook[0] not in APP_HOOKS)
    before = [item for item in hook_items if item[1] in BEFORE_HOOKS]
    after = [item for item in hook_items if item[1] in AFTER_HOOKS]
    if len(found) == 1:
        review.extend({'reason': 'response_processing_requires_review', 'source': item[3]} for item in after)
    unique_review = list({(issue['reason'], issue['source']['file_path'], issue['source']['line']): issue for issue in review}.values())
    report = {'entry': entry, 'match_count': len(found), 'review': unique_review[:16], 'review_count': len(unique_review),
              'decoded_path': decoded_path}
    if unrelated:
        report['unrelated_source_issues'] = unrelated
    if len(found) != 1:
        report['status'] = 'ambiguous' if found else 'incomplete' if review else 'not_found'
        report['candidates'] = [{'route': route['source'], 'rule': rule, 'converters': parameters, 'mounts': mounts}
                                for route, rule, parameters, mounts, _, _ in found[:8]]
        return report

    route_identified = all(issue['reason'] == 'response_processing_requires_review' for issue in review)
    report['status'] = 'matched' if route_identified else 'incomplete'
    report['route_identified'] = route_identified
    report['response_review_pending'] = any(issue['reason'] == 'response_processing_requires_review' for issue in review)
    report['trace'] = {
        'mounts': mounts, 'route': route['source'], 'rule': rule, 'converters': parameters,
        'hooks': [hook_details(item) for item in before[:8]], 'hook_count': len(before),
        'response_hooks': [hook_details(item) for item in after[:8]], 'response_hook_count': len(after),
        'handler': function_details(route['handler']),
    }
    if framework is not None:
        report['trace']['framework_response'] = framework
        if framework['kind'] != 'automatic_head':
            report['trace']['handler']['status_sites'] = []
            report['trace']['handler']['status_site_count'] = 0
    return report


if __name__ == '__main__':
    print(json.dumps(trace(json.load(sys.stdin)), ensure_ascii=True))
