from transformers import AutoModel

model = AutoModel.from_pretrained("acme/intent-classifier", trust_remote_code=True)
