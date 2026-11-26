import os
import runpy

if __name__ == '__main__':
    runpy.run_path(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'core', 'workers', 'flask-route-worker.py'),
        run_name='__main__',
    )
