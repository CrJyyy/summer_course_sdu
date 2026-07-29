from transformers import pipeline

model = pipeline(
    "text-generation",
    model="Qwen/Qwen2.5-0.5B-Instruct",
    device="cuda",
    dtype="float16",
)

messages = [
    {
        "role": "system",
        "content": "你是一个有帮助的中文助手。",
    },
    {
        "role": "user",
        "content": "请简单介绍你是什么模型。",
    },
]

result = model(
    messages,
    max_new_tokens=128,
    do_sample=False,
)

print(result[0]["generated_text"][-1]["content"])
