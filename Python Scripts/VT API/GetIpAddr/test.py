import json

def parse_json(json_input, examples):
  """Parses a JSON input and returns only the specified examples.

  Args:
    json_input: A JSON input string.
    examples: A list of strings that specify the desired examples.

  Returns:
    A list of dictionaries that contain the parsed examples.
  """

  data = json.loads(json_input)
  results = []
  for example in examples:
    if example in data:
      results.append(data[example])
  return results

if __name__ == "__main__":
  json_input ={
    "employees": [
      {
        "name": "John Doe",
        "age": 30,
        "city": "New York"
      },
      {
        "name": "Jane Doe",
        "age": 25,
        "city": "Los Angeles"
      }
    ]
  }

  examples = ["employees[0]", "employees[1]"]
  results = parse_json(json_input, examples)
  print(results)