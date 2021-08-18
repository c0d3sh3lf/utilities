#!/bin/bash

echo "Enter project name: "
read project_name
project_name=${project_name// /_}
project_name=`echo "$project_name" | awk '{ print tolower($1) }'`
echo "Folder will be created with '$project_name' in '$(pwd)' directory!"

# create project directory
mkdir $project_name
cd $project_name

# Create python virtual environment
virtualenv venv
. venv/bin/activate

# Update python and add requirements file
pip install --upgrade pip
pip freeze > requirements.txt

# Create Script File
touch $project_name.py
