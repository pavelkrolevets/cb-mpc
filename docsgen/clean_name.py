import json
import re

# Input and output file paths
input_file = 'docsgen/data/raw_aggregated_benchmarks.json'
output_file = 'docsgen/data/aggregated_benchmarks.json'

# Regular expression to match /iterations:<digits>
iterations_pattern = re.compile(r'/iterations:\d+')

# Load the JSON data
with open(input_file, 'r') as f:
    data = json.load(f)


benchmarks = data.get("benchmarks", [])
for entry in benchmarks:
    if 'name' in entry:
        # Remove /manual_time
        entry['name'] = entry['name'].replace('/manual_time', '')
        # Remove /iterations:<number>
        entry['name'] = iterations_pattern.sub('', entry['name'])
    
    if 'run_name' in entry:
        # Remove /manual_time
        entry['run_name'] = entry['run_name'].replace('/manual_time', '')
        # Remove /iterations:<number>
        entry['run_name'] = iterations_pattern.sub('', entry['run_name'])

# Write the updated data to a new file
with open(output_file, 'w') as f:
    json.dump(data, f, indent=2)