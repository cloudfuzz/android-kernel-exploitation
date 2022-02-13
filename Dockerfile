FROM ubuntu:18.04

# Fetch all essential packages for building the kernel
RUN apt-get update
RUN apt-get install -y git-core gnupg flex bison build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 libncurses5 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig wget python3 git make clang gcc bc
RUN curl https://storage.googleapis.com/git-repo-downloads/repo > /bin/repo
RUN chmod +x /bin/repo

# Get env ready for fetching source code of kernel
RUN git config --global user.email "you@example.com" && \
    git config --global user.name "Your Name"