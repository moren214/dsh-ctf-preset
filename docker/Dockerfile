# DSH CTF Preset 基础全栈 Linux 兵器库镜像（dsh-ctf-sandbox:latest）
# 构建命令（在 ctf-preset 目录执行）：
#   docker build -t dsh-ctf-sandbox:latest docker/
# 可选参数：
#   --build-arg WITH_R2=0                                     跳过 radare2/r2ghidra 以加速构建
#   --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple  使用国内 pip 镜像源
FROM ubuntu:24.04

ARG WITH_R2=1
ARG PIP_INDEX_URL=""
ARG RADARE2_VERSION=5.9.8
ARG GEF_VERSION=2025.01
ARG BKCRACK_VERSION=1.7.1
ARG FFUF_VERSION=2.1.0
ARG PWNINIT_VERSION=3.3.1

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

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

# 2. x86-64 宿主补充 32 位 ELF 运行库（避免跑 32 位 Pwn 题报 No such file）
RUN if [ "$(dpkg --print-architecture)" = "amd64" ]; then \
        dpkg --add-architecture i386 \
        && apt-get update \
        && apt-get install -y --no-install-recommends libc6:i386 libstdc++6:i386 \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# 3. 高频 Pwn / Rev / Crypto / Web / 内存取证 Python 兵器库
RUN PIP_ARGS="--no-cache-dir" \
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
        numpy \
        scipy \
        scapy \
        xdis \
        pyinstxtractor-ng

# 4. Ruby 兵器库（seccomp-tools / one_gadget / zsteg）
RUN gem install --no-document seccomp-tools one_gadget zsteg

# 4.5 高频独立安全工具（bkcrack / ffuf / pwninit，锁定版本）
RUN ARCH="$(dpkg --print-architecture)" \
    && if [ "$ARCH" = "amd64" ]; then \
        curl -fsSL "https://github.com/kimci86/bkcrack/releases/download/v${BKCRACK_VERSION}/bkcrack-${BKCRACK_VERSION}-Linux.tar.gz" -o /tmp/bkcrack.tgz \
        && mkdir -p /opt/bkcrack && tar -xzf /tmp/bkcrack.tgz -C /opt/bkcrack --strip-components=1 \
        && ln -sf /opt/bkcrack/bkcrack /usr/local/bin/bkcrack \
        && rm -f /tmp/bkcrack.tgz \
        && curl -fsSL "https://github.com/io12/pwninit/releases/download/${PWNINIT_VERSION}/pwninit" -o /usr/local/bin/pwninit \
        && chmod +x /usr/local/bin/pwninit; \
    fi \
    && FFUF_ARCH="$( [ "$ARCH" = "arm64" ] && echo arm64 || echo amd64 )" \
    && curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${FFUF_ARCH}.tar.gz" -o /tmp/ffuf.tgz \
    && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm -f /tmp/ffuf.tgz

# 5. GDB 增强插件 GEF（锁定发行版标签；gdb_driver 默认带 -nx 不受干扰，ctf_sandbox exec 跑 gdb 时直接生效）
RUN mkdir -p /opt/gef \
    && curl -fsSL "https://raw.githubusercontent.com/hugsy/gef/${GEF_VERSION}/gef.py" -o /opt/gef/gef.py \
    && echo "source /opt/gef/gef.py" > /root/.gdbinit

# 6. radare2 + r2ghidra 伪 C 反编译引擎（锁定稳定标签，传 --build-arg WITH_R2=0 可跳过）
RUN if [ "$WITH_R2" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends cmake ninja-build meson \
        && rm -rf /var/lib/apt/lists/* \
        && git clone --depth 1 --branch "${RADARE2_VERSION}" https://github.com/radareorg/radare2 /opt/radare2 \
        && /opt/radare2/sys/install.sh \
        && (r2pm -U && r2pm -ci r2ghidra || echo "WARN: r2ghidra optional plugin install failed; r2 + pdc still available" >&2) \
        && rm -rf /opt/radare2/.git; \
    fi

WORKDIR /work
CMD ["bash"]
