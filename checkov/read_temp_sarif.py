import ast
from collections import Counter

def read_lists_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            lists = [ast.literal_eval(line.strip()) for line in content.split('\n') if line.strip()]
            return lists
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except SyntaxError:
        print(f"Error: Unable to parse the lists in the file.")
        return None


# Example usage
file_path = 'results_backup.sarif'
lists_from_file = read_lists_from_file(file_path)

issue_count = 0

rule_id_all = []


if lists_from_file:
    print("Lists from file:")
    for lst in lists_from_file:
        for result in lst:
            issue_count += 1
            rule_id = result['ruleId']
            rule_id_all.append(rule_id)
            message = result['message']
            location = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            region = result["locations"][0]["physicalLocation"]["region"]
            print(rule_id)
            print(message)
            print(location)
            print(region)
            print('\n')



print(f'Total Issues count: {issue_count}')

rule_count = Counter(rule_id_all)

print(rule_count)
