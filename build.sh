# Create New Zip File
zip -9 nfcu_alexa_skill.zip lambda_function.py

# Install Requirements
source venv/bin/activate 
pip install -r requirements.txt

# Add NFCU Module
zip -ur -9 nfcu_alexa_skill.zip nfcu/ -i \*.py
zip -ur -9 nfcu_alexa_skill.zip nfcu/ -i \*.json

# Add Dependencies to Zip
cd venv/lib/python2.7/site-packages
zip -ur -9 ~/Projects/Personal/Alexa/nfcu/nfcu_alexa_skill.zip * -i \*.py \*.pem
