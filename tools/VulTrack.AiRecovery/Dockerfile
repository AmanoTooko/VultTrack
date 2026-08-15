# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src
COPY tools/VulTrack.AiRecovery/VulTrack.AiRecovery.csproj ./
COPY tools/VulTrack.AiRecovery/Program.cs ./
RUN case "$TARGETARCH" in \
      amd64) rid=linux-x64 ;; \
      arm64) rid=linux-arm64 ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac && \
    dotnet restore VulTrack.AiRecovery.csproj -r "$rid" && \
    dotnet publish VulTrack.AiRecovery.csproj -c Release -r "$rid" --self-contained false --no-restore -o /out

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /recovery
COPY --from=build /out/ ./
ENTRYPOINT ["dotnet", "/recovery/VulTrack.AiRecovery.dll"]
