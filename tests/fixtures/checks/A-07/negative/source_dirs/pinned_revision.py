from transformers import AutoModel

model = AutoModel.from_pretrained(
    "acme/intent-classifier", revision="4f1c2a9", trust_remote_code=False
)
