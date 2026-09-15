# llm_delivery_pipeline

PoC of a confidential distribution pipeline for LLM/ML models (Layer 1).

## Source model compatibility

`produce` only accepts a source model whose `config.json` declares a
`model_type`, since that is what lets `transformers` auto-detect its
architecture on the consumer side. Some older Hugging Face repos omit this
key; publishing one of those is rejected immediately, before any encryption
or upload happens, with an error naming the missing key.

