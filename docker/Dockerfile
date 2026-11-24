# DSH CTF Preset 基础全栈 Linux 兵器库镜像（dsh-ctf-sandbox:latest）
# 构建命令（在 ctf-preset 目录执行）：
#   docker build -t dsh-ctf-sandbox:latest docker/
# 可选参数：
#   --build-arg WITH_R2=0                                     跳过 radare2/r2ghidra 以加速构建
#   --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple  使用国内 pip 镜像源
# 基础镜像按 digest 固定（多架构索引），tag 漂移不会改变构建结果；如需换源可显式覆盖该 ARG。
ARG UBUNTU_BASE_IMAGE=ubuntu:24.04@sha256:9a04f13b3f80ef056361e30868593b1cfd2279fe19e4081cb93a90bf56819d6a
FROM ${UBUNTU_BASE_IMAGE}

ARG WITH_R2=1
ARG PIP_INDEX_URL=""
ARG APT_MIRROR=""
ARG GITHUB_BASE_URL=https://github.com
ARG GITHUB_RAW_BASE_URL=https://raw.githubusercontent.com
ARG RUBYGEMS_SOURCE_URL=https://rubygems.org
ARG RADARE2_VERSION=5.9.8
# r2ghidra 必须与 radare2 主版本成对锁定：master 跟随 r2 的 ABI 变动（5.9.8 上会撞
# `RFlagItem has no member named 'addr'` / `r_anal_cc_argloc` 未声明），这里钉同号 tag。
ARG R2GHIDRA_VERSION=5.9.8
ARG GEF_VERSION=2025.01
ARG BKCRACK_VERSION=1.7.1
ARG FFUF_VERSION=2.1.0
ARG PWNINIT_VERSION=3.3.1
# 下载物校验和：锁定版本的同时锁定字节，GitHub 上的 release 被替换会在这里失败而不是静默进入镜像。
ARG BKCRACK_SHA256=38dc3ae78923474b769ab1969bb2cffcbc501a90fde6bf68a6410f7ccf25c0f5
ARG PWNINIT_SHA256=1b72653be59f8f13ea934d1153e8d845eac0dbac62a8c4d9dc4a25577f009362
ARG FFUF_SHA256_AMD64=fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5
ARG GEF_SHA256=cf5795a042585d3791e5d63880050364f6338c10a91b409e530391c2391fe48d

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Optional complete apt mirror for Ubuntu noble, including noble-security.
RUN if [ -n "$APT_MIRROR" ]; then \
        case "$APT_MIRROR" in http://*|https://*) ;; *) echo "APT_MIRROR must be an http(s) URL" >&2; exit 2;; esac; \
        sed -i "s|http://archive.ubuntu.com/ubuntu|${APT_MIRROR}|g; s|http://security.ubuntu.com/ubuntu|${APT_MIRROR}|g; s|http://ports.ubuntu.com/ubuntu-ports|${APT_MIRROR}|g" /etc/apt/sources.list.d/ubuntu.sources; \
    fi

# 1. 核心系统安全/逆向/取证/Web 运行时工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    xz-utils \
    cpio \
    file \
    xxd \
    jq \
    sqlite3 \
    p7zip-full \
    wabt \
    sleuthkit \
    netcat-openbsd \
    socat \
    dnsutils \
    gdb \
    gdb-multiarch \
    binutils \
    patchelf \
    checksec \
    strace \
    ltrace \
    upx-ucl \
    qemu-user \
    binwalk \
    steghide \
    tshark \
    libimage-exiftool-perl \
    pngcheck \
    zbar-tools \
    tesseract-ocr \
    john \
    sqlmap \
    sox \
    ffmpeg \
    php-cli \
    nodejs \
    python3 \
    python3-pip \
    python3-dev \
    python3-fpylll \
    ruby \
    ruby-dev \
    gcc \
    g++ \
    make \
    pkg-config \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/*

ENV PATH=/opt/ctf-venv/bin:$PATH

# 2. x86-64 宿主补充 32 位 ELF 运行库（避免跑 32 位 Pwn 题报 No such file）
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        dpkg --add-architecture i386 \
        && apt-get update \
        && apt-get install -y --no-install-recommends libc6:i386 libstdc++6:i386 \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# 3. 高频 Pwn / Rev / Crypto / Web / 内存取证 Python 兵器库
RUN python3 -m venv --system-site-packages /opt/ctf-venv \
    && PIP_ARGS="--no-cache-dir" \
    && if [ -n "$PIP_INDEX_URL" ]; then PIP_ARGS="$PIP_ARGS -i $PIP_INDEX_URL"; fi \
    && pip3 install $PIP_ARGS \
        pwntools \
        ROPgadget \
        ropper \
        capstone \
        z3-solver \
        pycryptodome \
        sympy \
        gmpy2 \
        ecdsa \
        pyjwt \
        itsdangerous \
        requests \
        beautifulsoup4 \
        flask \
        volatility3 \
        pillow \
        "numpy<2" \
        scipy \
        scapy \
        xdis \
        pyinstxtractor-ng

# 4.5 高频独立安全工具（bkcrack / ffuf / pwninit，锁定版本）
RUN ARCH="$(dpkg --print-architecture)" \
    && if [ "$ARCH" = "amd64" ]; then \
        curl -fsSL "${GITHUB_BASE_URL}/kimci86/bkcrack/releases/download/v${BKCRACK_VERSION}/bkcrack-${BKCRACK_VERSION}-Linux.tar.gz" -o /tmp/bkcrack.tgz \
        && echo "${BKCRACK_SHA256}  /tmp/bkcrack.tgz" | sha256sum -c - \
        && mkdir -p /opt/bkcrack && tar -xzf /tmp/bkcrack.tgz -C /opt/bkcrack --strip-components=1 \
        && ln -sf /opt/bkcrack/bkcrack /usr/local/bin/bkcrack \
        && rm -f /tmp/bkcrack.tgz \
        && curl -fsSL "${GITHUB_BASE_URL}/io12/pwninit/releases/download/${PWNINIT_VERSION}/pwninit" -o /usr/local/bin/pwninit \
        && echo "${PWNINIT_SHA256}  /usr/local/bin/pwninit" | sha256sum -c - \
        && chmod +x /usr/local/bin/pwninit; \
    fi \
    && FFUF_ARCH="$( [ "$ARCH" = "arm64" ] && echo arm64 || echo amd64 )" \
    && curl -fsSL "${GITHUB_BASE_URL}/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${FFUF_ARCH}.tar.gz" -o /tmp/ffuf.tgz \
    && if [ "$FFUF_ARCH" = "amd64" ]; then echo "${FFUF_SHA256_AMD64}  /tmp/ffuf.tgz" | sha256sum -c -; fi \
    && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm -f /tmp/ffuf.tgz

# 5. GDB 增强插件 GEF（锁定发行版标签；gdb_driver 默认带 -nx 不受干扰，ctf_sandbox exec 跑 gdb 时直接生效）
RUN mkdir -p /opt/gef \
    && curl -fsSL "${GITHUB_RAW_BASE_URL}/hugsy/gef/${GEF_VERSION}/gef.py" -o /opt/gef/gef.py \
    && echo "${GEF_SHA256}  /opt/gef/gef.py" | sha256sum -c - \
    && echo "source /opt/gef/gef.py" > /root/.gdbinit

# 6a. radare2（`patch` 是 configure 的硬性依赖，缺了会 error: This program is required.）
#     必须用 `--install` 语义而不是 sys/install.sh 的默认 symstall：symstall 把 /usr/local/bin/r2
#     软链到构建目录，删掉 /tmp/radare2 后 r2 与 r_core.pc 全部悬空（r2ghidra 会报
#     `checking pkg-config flags for r_core... no`）。
RUN if [ "$WITH_R2" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends cmake ninja-build meson patch \
        && rm -rf /var/lib/apt/lists/* \
        && git clone --depth 1 --branch "${RADARE2_VERSION}" "${GITHUB_BASE_URL}/radareorg/radare2" /tmp/radare2 \
        && cd /tmp/radare2 && ./configure --prefix=/usr/local && make -j"$(nproc)" && make install && cd / \
        && ldconfig && r2 -v | head -1 \
        && rm -rf /tmp/radare2; \
    fi

# 6b. r2ghidra 伪 C 反编译插件
#     必须与 radare2 同号锁定：r2pm 的在线安装取的是 master 分支，在 r2 5.9.8 上会撞
#     `RFlagItem has no member named 'addr'` / `r_anal_cc_argloc` 未声明（ABI 已变）。
#     该 tag 只有 Makefile.acr，需先 ./configure 才会生成 Makefile（configure 会向
#     `r2 -H R2_LIBR_PLUGINS` 查询插件安装目录，因此上一步必须先装好 r2）。
RUN if [ "$WITH_R2" = "1" ]; then \
        git clone --depth 1 --branch "${R2GHIDRA_VERSION}" "${GITHUB_BASE_URL}/radareorg/r2ghidra" /tmp/r2ghidra \
        && cd /tmp/r2ghidra && ./configure && make -j"$(nproc)" && make install \
        && cd / && rm -rf /tmp/r2ghidra \
        && apt-get purge -y --auto-remove cmake ninja-build meson \
        && rm -rf /var/lib/apt/lists/*; \
    fi

RUN if [ "$RUBYGEMS_SOURCE_URL" = "https://rubygems.org" ]; then \
        gem install --no-document seccomp-tools one_gadget zsteg; \
    else \
        gem install --no-document --source "$RUBYGEMS_SOURCE_URL" seccomp-tools one_gadget zsteg; \
    fi

RUN groupadd --gid 10001 ctf \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash ctf \
    && mkdir -p /work \
    && if [ -f /root/.gdbinit ]; then cp /root/.gdbinit /home/ctf/.gdbinit; fi \
    && if [ -d /root/.local/share/radare2 ]; then \
        mkdir -p /home/ctf/.local/share \
        && cp -a /root/.local/share/radare2 /home/ctf/.local/share/radare2; \
    fi \
    && chown -R ctf:ctf /work /home/ctf

WORKDIR /work
USER 10001:10001
CMD ["bash"]
