import questionary
import oxide_validator.generate_config as gen
import json

original_text = questionary.text
original_confirm = questionary.confirm

answers = []
confirmations = []

def wrapped_text(prompt):
    answer = original_text(prompt).ask()
    answers.append(answer)
    return answer

def wrapped_confirm(prompt):
    result = original_confirm(prompt).ask()
    confirmations.append(result)
    return result

gen.questionary.text = lambda prompt: type("Q", (), {"ask": lambda self=None: wrapped_text(prompt)})()
gen.questionary.confirm = lambda prompt: type("Q", (), {"ask": lambda self=None: wrapped_confirm(prompt)})()

# Run interactively
gen.generate_config()

# Output recorded values
print("\n--- Paste into your test ---")
print("mock_text().ask.side_effect = [")
for a in answers:
    print(f"    {json.dumps(a)},")
print("]")
print("mock_confirm().ask.side_effect = [")
for c in confirmations:
    print(f"    {json.dumps(c)},")
print("]")