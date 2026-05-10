FROM mcr.microsoft.com/dotnet/sdk:10.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace/src/VulTrack.App

CMD ["dotnet", "run", "--urls", "http://0.0.0.0:8080"]
