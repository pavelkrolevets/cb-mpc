import yaml

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def replace_text(file_path, rules):
    try:
        with open(file_path, 'r') as file:
            content = file.read()

        for old_text, new_text in rules.items():
            content = content.replace(old_text, new_text)

        with open(file_path, 'w') as file:
            file.write(content)

        print(f"Replaced text in {file_path}")
    except FileNotFoundError:
        print(f"File {file_path} not found.")

if __name__ == "__main__":
    yaml_file = 'docsgen/benchmark_name.yml'

    config = load_yaml(yaml_file)
    files = config['files']
    rules = config['benchmark_name_map']

    for file_path in files:
        replace_text(file_path, rules)

    print("Text replacement complete.")