# Create New Zip File
zip -9 nfcu_alexa_skill.zip lambda_function.py

# Install Requirements
source venv/bin/activate 
pip install -r requirements.txt

# Add NFCU Module
zip -ur -9 nfcu_alexa_skill.zip nfcu/ -i \*.py

# Add Dependencies to Zip
zip -ur -9 nfcu_alexa_skill.zip venv/lib/python3.5/site-packages/ -i \*.py
