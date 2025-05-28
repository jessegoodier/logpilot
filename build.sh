#!/bin/bash

set -euo pipefail

# --- CONFIGURATION ---
REGISTRY="docker.io/jgoodier"
IMAGE_NAME="python-log-viewer"
DOCKERFILE="Dockerfile"
CONTEXT="."
TAG="0.0.6"

FULL_NAME_AMD64="${REGISTRY}/${IMAGE_NAME}:amd64"
FULL_NAME_ARM64="${REGISTRY}/${IMAGE_NAME}:arm64"
FULL_NAME_MULTI="${REGISTRY}/${IMAGE_NAME}:${TAG}"
MANIFEST_NAME="${REGISTRY}/${IMAGE_NAME}:manifest-${TAG}"

# --- BUILD ARCH-SPECIFIC IMAGES ---
echo "🔨 Building AMD64 image..."
podman build --arch amd64 -f "$DOCKERFILE" -t "$FULL_NAME_AMD64" "$CONTEXT"

echo "🔨 Building ARM64 image..."
podman build --arch arm64 -f "$DOCKERFILE" -t "$FULL_NAME_ARM64" "$CONTEXT"

# --- PUSH ARCH-SPECIFIC IMAGES ---
echo "📤 Pushing AMD64 image..."
podman push "$FULL_NAME_AMD64"

echo "📤 Pushing ARM64 image..."
podman push "$FULL_NAME_ARM64"

# --- CREATE MANIFEST LIST ---
echo "📦 Creating manifest list..."
podman manifest create "$MANIFEST_NAME"

echo "➕ Adding images to manifest..."
podman manifest add "$MANIFEST_NAME" "$FULL_NAME_AMD64"
podman manifest add "$MANIFEST_NAME" "$FULL_NAME_ARM64"

# --- TAG AND PUSH MANIFEST ---
echo "🏷️ Tagging manifest as $FULL_NAME_MULTI..."
podman tag "$MANIFEST_NAME" "$FULL_NAME_MULTI"

echo "📤 Pushing multi-arch image to $REGISTRY..."
podman manifest push --all "$FULL_NAME_MULTI"

echo "✅ Done! Multi-arch image pushed to: $FULL_NAME_MULTI"