import ijson

with open("data/diversevul_20230702.json", "rb") as f:
    parser = ijson.items(f, "", multiple_values=True)
    for i, item in enumerate(parser):
        if isinstance(item, dict):
            print("Keys:", item.keys())
            print("Sample file_path:", item.get("file_path"))
            print("Sample project:", item.get("project"))
            print("Sample programming_language:", item.get("programming_language"))
            break
