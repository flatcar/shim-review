FROM ghcr.io/flatcar/flatcar-sdk-all:4054.0.0

ARG SCRIPTS_REPO_URL=https://github.com/flatcar/scripts.git
ARG SCRIPTS_WORK_DIR=/mnt/host/source/src/scripts

# Clone the scripts repo
WORKDIR /mnt/host/source/src/scripts/
RUN git clone $SCRIPTS_REPO_URL .
RUN git -C $SCRIPTS_WORK_DIR fetch --tags
RUN git -C $SCRIPTS_WORK_DIR checkout main

ADD flatcar-dev-ca.der .

COPY --chown=sdk:sdk . /mnt/host/source/src/scripts

RUN chown sdk:sdk /mnt/host/source
RUN ln -s /mnt/host/source/src/scripts/sdk_container/src/third_party /mnt/host/source/src/
ENV SOURCE_DATE_EPOCH=1
ENV USE=official
ENV SHIM_SIGNING_CERTIFICATE=/mnt/host/source/src/scripts/flatcar-dev-ca.der
RUN wget -O /mnt/host/source/.cache/distfiles/shim-15.8.tar.bz2 https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2
RUN emerge-amd64-usr --nodeps shim
RUN emerge-arm64-usr --nodeps shim

WORKDIR /shim-review
RUN sha256sum /mnt/host/source/.cache/distfiles/shim-15.8.tar.bz2 | tee shim-tar-bz2.sha256
RUN sha256sum /build/amd64-usr/usr/lib/shim/shimx64.efi | tee shimx64-15.8.sha256
RUN sha256sum /build/arm64-usr/usr/lib/shim/shimaa64.efi | tee shimaa64-15.8.sha256
RUN cp /build/amd64-usr/usr/lib/shim/shimx64.efi shimx64-15.8.efi
RUN cp /build/arm64-usr/usr/lib/shim/shimaa64.efi shimaa64-15.8.efi
RUN objcopy --only-section .sbat -O binary shimx64-15.8.efi /dev/stdout | tee sbat-shimx64-15.8.csv
RUN aarch64-cros-linux-gnu-objcopy --only-section .sbat -O binary /shim-review/shimaa64-15.8.efi /dev/stdout | tee sbat-shimaa64-15.8.csv
RUN hexdump -Cv shimx64-15.8.efi > shimx64-build
RUN hexdump -Cv shimaa64-15.8.efi > shima64-build
