from flask import Flask, request, render_template, jsonify
import base64
import re
import json
import io
import pdfplumber
import os
import hashlib

app = Flask(__name__)


def pdf_to_base64(pdf_path):
    """Convert PDF file to base64 string"""
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"PDF file not found at: {pdf_path}")
    with open(pdf_path, 'rb') as pdf_file:
        encoded_string = base64.b64encode(pdf_file.read())
        return encoded_string.decode('utf-8')


def base64_to_text(base64_string):
    """Convert base64 string back to text from PDF"""
    try:
        decoded_data = base64.b64decode(base64_string)
    except Exception as e:
        raise ValueError(f"Invalid base64 string: {str(e)}")

    pdf_file = io.BytesIO(decoded_data)
    text = ""
    with pdfplumber.open(pdf_file) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            text += page_text + "\n"

    return text, decoded_data


def validate_base64_string(base64_string, original_pdf_path):
    """Validate the base64 string and verify decoded PDF matches original"""
    try:
        # Decode base64 string
        try:
            decoded_data = base64.b64decode(base64_string)
        except Exception as e:
            return False, f"Base64 string is invalid: {str(e)}"

        # Save decoded data as a PDF
        decoded_pdf_path = "decoded_output.pdf"
        with open(decoded_pdf_path, 'wb') as f:
            f.write(decoded_data)

        # Compare file hashes
        original_hash = get_file_hash(original_pdf_path)
        decoded_hash = get_file_hash(decoded_pdf_path)
        if original_hash != decoded_hash:
            return False, "File hashes do not match: decoded PDF differs from original"

        # Verify decoded PDF is readable
        try:
            with pdfplumber.open(decoded_pdf_path) as pdf:
                if not pdf.pages:
                    return False, "Decoded PDF is empty or unreadable"
        except Exception as e:
            return False, f"Decoded PDF is invalid: {str(e)}"

        return True, "Base64 string is correct"

    except Exception as e:
        return False, f"Validation error: {str(e)}"
    finally:
        if os.path.exists(decoded_pdf_path):
            os.remove(decoded_pdf_path)


def get_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_data_to_json(text):
    """Extract structured data from text and convert to JSON format"""
    result = {}
    categories = [
        "Allergies", "Behavioral Changes", "Benefits", "Cardiovascular",
        "Chronic Subclinical Inflammation", "Hormones", "Injuries",
        "Instability", "Internalizations", "Metabolic", "Muscular System",
        "Hand Grip Strength", "Personal Characteristics", "Provocative",
        "Psychiatric", "Reason For Conflict", "Respiratory System",
        "Skeletal System (Bones)", "Skin", "Sports", "Vision (Ophthalmology)",
        "Weight"
    ]

    for cat in categories:
        result[cat] = {}

    text = text.replace('•', '-').replace('$', '').replace(r'\mathrm{O}', 'O')
    lines = text.split('\n')
    current_category = None
    data_pattern = re.compile(
        r'-\s*(.*?):\s*(\d+\s*-\s*\d+\s*\+\s*\d+\s*\+\+\s*(O)?\s*(MEDIUM-HIGH|HIGH|MEDIUM|LOW|NORMAL))'
    )

    for line in lines:
        line = line.strip()
        if not line:
            continue

        matched_category = None
        for cat in categories:
            if line.strip() == cat:
                matched_category = cat
                break

        if matched_category:
            current_category = matched_category
            continue

        if current_category:
            match = data_pattern.search(line)
            if match:
                item_name = match.group(1).strip()
                rating = match.group(4).strip()
                result[current_category][item_name] = rating

    return {k: v for k, v in result.items() if v}


@app.route('/', methods=['GET'])
def index():
    """Render the upload form"""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_pdf():
    """Handle PDF upload, process it, and return JSON"""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if not file.filename.endswith('.pdf'):
        return jsonify({"error": "File must be a PDF"}), 400

    try:
        # Save uploaded file temporarily
        temp_path = "temp_uploaded.pdf"
        file.save(temp_path)

        # Convert to base64
        base64_string = pdf_to_base64(temp_path)

        # Validate base64 string
        is_valid, validation_message = validate_base64_string(base64_string, temp_path)
        if not is_valid:
            os.remove(temp_path)
            return jsonify({"error": validation_message}), 400

        # Extract text
        text, _ = base64_to_text(base64_string)

        # Extract data to JSON
        data = extract_data_to_json(text)

        # Create final result
        final_result = {
            "base64_string": base64_string,
            "extracted_data": data
        }

        # Save JSON to file
        output_file = 'output.json'
        with open(output_file, 'w') as f:
            json.dump(final_result, f, indent=2)

        # Clean up temporary file
        os.remove(temp_path)

        # Return JSON response
        return jsonify(final_result), 200

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)