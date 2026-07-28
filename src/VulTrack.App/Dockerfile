FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build

WORKDIR /src
COPY src/VulTrack.App/VulTrack.App.csproj src/VulTrack.App/
RUN dotnet restore src/VulTrack.App/VulTrack.App.csproj
COPY src/VulTrack.App/ src/VulTrack.App/
RUN dotnet publish src/VulTrack.App/VulTrack.App.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish

FROM node:22-bookworm-slim AS node-runtime

WORKDIR /workspace
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY plugins/ ./plugins/
COPY scripts/ ./scripts/
COPY prompts/ ./prompts/

FROM mcr.microsoft.com/dotnet/aspnet:10.0

RUN sed -i 's|http://ports.ubuntu.com/ubuntu-ports|https://mirrors.aliyun.com/ubuntu-ports|g' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 install -y --fix-missing --no-install-recommends git ca-certificates bzip2 xz-utils unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/publish/ ./
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /workspace/node_modules /workspace/node_modules
COPY --from=node-runtime /workspace/plugins /workspace/plugins
COPY --from=node-runtime /workspace/scripts /workspace/scripts
COPY --from=node-runtime /workspace/prompts /workspace/prompts

ENV ASPNETCORE_URLS=http://0.0.0.0:8080
CMD ["dotnet", "/app/VulTrack.App.dll"]
