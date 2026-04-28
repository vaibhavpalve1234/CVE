import json
from datasets import Dataset
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer
from peft import LoraConfig, get_peft_model
import torch

MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"

# Load dataset
with open("data/processed/cve_dataset.json") as f:
    data = json.load(f)

# Reduce dataset for low-resource training (IMPORTANT)
data = data[:2000]

def format_example(x):
    return {
        "text": f"""
### Instruction:
Explain {x['cve_id']}

### Response:
{{
  "cve_id": "{x['cve_id']}",
  "summary": "{x['description']}",
  "severity": "{x['severity']}",
  "impact": "Potential system compromise or data exposure",
  "mitigation": "Apply latest patches and restrict access"
}}
"""
    }

dataset = Dataset.from_list(data).map(format_example)

# Load tokenizer + model
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME)

# LoRA config (lightweight)
lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05
)

model = get_peft_model(model, lora_config)

# Tokenize
def tokenize(x):
    return tokenizer(x["text"], truncation=True, padding="max_length", max_length=512)

dataset = dataset.map(tokenize, batched=True)

# Training args
training_args = TrainingArguments(
    output_dir="models/slm",
    per_device_train_batch_size=1,
    gradient_accumulation_steps=4,
    num_train_epochs=1,
    logging_steps=10,
    save_steps=100,
    fp16=torch.cuda.is_available()
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset
)

trainer.train()

model.save_pretrained("models/slm")
tokenizer.save_pretrained("models/slm")

print("✅ LoRA training complete")