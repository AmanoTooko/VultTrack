FROM mcr.microsoft.com/dotnet/sdk:10.0

RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --fix-missing --no-install-recommends nodejs npm git ca-certificates bzip2 xz-utils unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/src/VulTrack.App

CMD ["dotnet", "run", "--urls", "http://0.0.0.0:8080"]
