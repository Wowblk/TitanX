#!/bin/bash

# 设置输出文件
structure_file="data/project_structure.txt"
source_file="data/source_code.txt"

mkdir -p data

# 清空或创建输出文件
rm "$structure_file"
rm "$source_file"

# 打印项目目录结构到 structure_file
tree -I 'vendor|node_modules|googleapis|grpc-proto|.git' >> "$structure_file"

# 遍历所有目标文件类型并追加内容到 source_file

# 定义要包含的文件类型
file_types=("*.go" "Makefile" "*.proto" "*.yaml" "*.yml" "go.mod")

for type in "${file_types[@]}"; do
    find . -name "$type" -not -path "*/vendor/*" -not -path "*/proto/lib/googleapis/*" -not -path "*/proto/lib/grpc-proto/*" -not -path "*/node_modules/*" | while read -r file; do
        echo -e "\n\n----------------\nFile: $file" >> "$source_file"
        echo "----------------" >> "$source_file"
        cat "$file" >> "$source_file"
    done
done

echo "Done! Output saved to:"
echo "Project structure: $structure_file"
echo "Source code: $source_file"
