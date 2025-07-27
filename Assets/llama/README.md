# Llama AI Model Directory

This directory contains the AI model files required for generating migration reports.

## Required Files

Please manually add the following files to this directory:

- **llama.exe** - Prebuilt llama executable for CPU inference
- **model.gguf** - The .gguf format model file for text generation

## Notes

- The llama.exe should be compatible with your target platform
- The model.gguf file contains the AI model weights in GGUF format
- These files enable offline AI-powered migration report generation
- Ensure the model file is compatible with the llama executable version