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
pip install flask
pip freeze > requirements.txt

# Create a dockerfile
echo "FROM python:3.9-alpine" > Dockerfile
echo "ENV PYTHONBUFFERED 1" >> Dockerfile
echo "RUN mkdir /app" >> Dockerfile
echo "WORKDIR /app" >> Dockerfile
echo "ADD requirements.txt /app/" >> Dockerfile
echo "RUN apk update \\" >> Dockerfile
echo "    && apk add --virtual build-deps gcc python3-dev musl-dev \\" >> Dockerfile
echo "    && apk add --no-cache mariadb-dev freetype-dev jpeg-dev zlib-dev libjpeg" >> Dockerfile
echo "RUN pip install --upgrade pip && pip install -r requirements.txt" >> Dockerfile
echo "RUN apk del build-deps" >> Dockerfile
echo "ADD ./ /app/" >> Dockerfile

# Create a docker-compose file
echo "version: \"3\"" > docker-compose.yml
echo "" >> docker-compose.yml
echo "services:" >> docker-compose.yml
echo "  web:" >> docker-compose.yml
echo "    build: ." >> docker-compose.yml
echo "    command: python app.py " >> docker-compose.yml
echo "    volumes:" >> docker-compose.yml
echo "      - ./:/app" >> docker-compose.yml
echo "    ports:" >> docker-compose.yml
echo "      - \"5000:5000\"" >> docker-compose.yml

# Create Flask App
echo "from flask import Flask" > app.py
echo "app = Flask(__name__)" >> app.py
echo "" >> app.py
echo "@app.route('/')" >> app.py
echo "def index():" >> app.py
echo "  return \"This app works!\"" >> app.py
echo "" >> app.py
echo "if __name__ == \"__main__\":" >> app.py
echo "  app.run(debug=True)" >> app.py