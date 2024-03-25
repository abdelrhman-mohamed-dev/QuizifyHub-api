from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
#from jwt import encode
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import json
import os


app = Flask(__name__)

#QuizifyHub-api

app.config["SECRET_KEY"] = "mysecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
# postgresql://questgen_user:girz2SJq0pu2QQk2SDy2AL9FJTSorEai@dpg-cns54kdjm4es73a7hm4g-a.oregon-postgres.render.com/questgen
# app.config["UpLOAD_FOLDER"] = "/home/user/questgen/src/uploads"
app.config["ALLOWED_EXTENSIONS"] = {"pdf"}


db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    admin = db.Column(db.Boolean, default=False, nullable=False)
    activated = db.Column(db.Boolean, default=False, nullable=False)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(), unique=True, nullable=False)
    pdf_file = db.Column(db.String(255), unique=True, nullable=False)
    questions_number = db.Column(db.Integer, nullable=False)
    questions_type = db.Column(db.String(50), nullable=False)
    shared = db.Column(db.Boolean, default=False, nullable=False)
   # user_id = db.Column(db.Integer, db.ForeignKey("user.public_id"), nullable=False)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            return jsonify({"message": "Token is missing!"})

        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data["public_id"]).first()
        except jwt.ExpiredSignatureError as e:
            return jsonify({"message": "Token has expired!"})
        except jwt.InvalidTokenError as e:
            return jsonify({"message": "Token is invalid!"})

        return f(current_user, *args, **kwargs)

    return decorated


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


@app.route("/", methods=["GET"])
def index():
    return "api working!"


@app.route("/api/v1/user", methods=["GET"])
@token_required
def get_all_users(current_user):

#    if not current_user.admin:
#        return jsonify({"message": "Cannot perform that function!"})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {
            "id": user.id,
            "public_id": user.public_id,
            "username": user.username,
            "email": user.email,
            "admin": user.admin,
            "activated": user.activated,
            "password": user.password,
        }
        output.append(user_data)
    return jsonify({"users": output})


@app.route("/api/v1/user/<public_id>", methods=["GET"])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"})
    user_data = {
        "public_id": user.public_id,
        "username": user.username,
        "email": user.email,
        "admin": user.admin,
        "activated": user.activated,
    }
    return jsonify({"user": user_data})


@app.route("/api/v1/user/<public_id>", methods=["PUT"])
@token_required
def update_user(current_user, public_id):

#    if not current_user.admin:
#        return jsonify({"message": "Cannot perform that function!"})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"})

    user.admin = True

    db.session.commit()

    user_data = {
        "id": user.id,
        "public_id": user.public_id,
        "username": user.username,
        "email": user.email,
        "admin": user.admin,
        "activated": user.activated,
    }
    return jsonify({"message": "User updated successfully", "user": user_data})


@app.route("/api/v1/user/<public_id>", methods=["DELETE"])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({"message": "Cannot perform that function!"})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "No user found!"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully!"})


@app.route("/api/v1/create-quiz", methods=["POST"])
@token_required
def create_quiz(current_user):
    # Check if the PDF file is present in the request files
    if "pdf_file" not in request.files:
        return jsonify({"message": "No PDF file part!"})

    # Access the PDF file from the request
    pdf_file = request.files["pdf_file"]

    # Check if questions_number is present in the form data
    if "questions_number" not in request.form:
        return jsonify({"message": "No questions number provided!"})
    questions_number = request.form["questions_number"]

    # Check if questions_type is present in the form data
    if "questions_type" not in request.form:
        return jsonify({"message": "No questions type provided!"})
    questions_type = request.form["questions_type"]

    # Further processing logic can go here

    # Save the PDF file to the uploads folder
    # pdf_file.save(os.path.join(app.config['UPLOAD_FOLDER'], pdf_file.filename))

    # Convert JSON content to string
    content = {
        "questions": {
            "questions": [
                {
                    "answer": "computer system",
                    "context": "The main device categories are: The main parts of a computer system are: Input devices These devices are used to get data into the computer system Processing devices These manipulate the data using to a set of instructions called a program Output devices These are used to get data out of a computer system Storage devices The can store the data for use at a later stage Communications devices These can send the data to another computer system 1 System Unit The container for the motherboard, disk drives etc. The main device categories are: The main parts of a computer system are: Input devices These devices are used to get data into the computer system Processing devices These manipulate the data using to a set of instructions called a program Output devices These are used to get data out of a computer system Storage devices The can store the data for use at a later stage Communications devices These can send the data to another computer system 1 System Unit The container for the motherboard, disk drives etc. The main device categories are: The main parts of a computer system are: Input devices These devices are used to get data into the computer system Processing devices These manipulate the data using to a set of instructions called a program Output devices These are used to get data out of a computer system Storage devices The can store the data for use at a later stage Communications devices These can send the data to another computer system 1 System Unit The container for the motherboard, disk drives etc.",
                    "extra_options": [
                        "Phone System",
                        "Physical Device",
                        "Security Protocols",
                    ],
                    "id": 1,
                    "options": ["Software Program", "Computer Network", "Mainframe"],
                    "options_algorithm": "sense2vec",
                    "question_statement": "What are the main parts of a computer system?",
                    "question_type": "MCQ",
                },
                {
                    "answer": "graphics cards",
                    "context": "The main parts of a graphics card are: Computers are often supplied with integrated graphics cards. This is called Scalable Link Interface (SLI) and it allows the two graphics cards to produce a single output. It also allows for the use of two graphics cards working in tandem to improve the performance.",
                    "extra_options": ["Processors"],
                    "id": 2,
                    "options": ["Video Cards", "Gpus", "Single Gpu"],
                    "options_algorithm": "sense2vec",
                    "question_statement": "What are the main parts of a graphics card?",
                    "question_type": "MCQ",
                },
                {
                    "answer": "software",
                    "context": "Examples include: • Motherboard • Hard disk • RAM • Power supply • Processor • Case • Monitor • Keyboard • Mouse Software: The term software is used to describe computer programs that perform a task or tasks on a computer system. Examples include: • Motherboard • Hard disk • RAM • Power supply • Processor • Case • Monitor • Keyboard • Mouse Software: The term software is used to describe computer programs that perform a task or tasks on a computer system. Software can be grouped as follows: • System software: These are the programs that control the operation of the computer system.",
                    "extra_options": [],
                    "id": 3,
                    "options": ["Hardware"],
                    "options_algorithm": "sense2vec",
                    "question_statement": "What is the term used to describe computer programs that perform a task on a computer system?",
                    "question_type": "MCQ",
                },
                {
                    "answer": "processor",
                    "context": "Below is shown typical power usage for a number of computer devices: • Motherboard: 60 watts • Processor: 90 watts • Memory: 10 watts/128MB • Processor fan: 5 watts • Graphics card: 40 watts • Hard disk: 25 watts • Optical drive: 30 watts As can be seen, a large power supply (at least 400 Watts) is preferable and does not use more energy as it only supplies power on demand. Below is shown typical power usage for a number of computer devices: • Motherboard: 60 watts • Processor: 90 watts • Memory: 10 watts/128MB • Processor fan: 5 watts • Graphics card: 40 watts • Hard disk: 25 watts • Optical drive: 30 watts As can be seen, a large power supply (at least 400 Watts) is preferable and does not use more energy as it only supplies power on demand. This is the speed of the system clock (clock speed) within the processor and it controls how fast instructions can be executed: • 1 MHz - One million clock ticks every second • 1 GHz - One billion clock ticks every second This means that if one instruction was executed every clock tick, a 3GHz processor could execute three billion instructions every second.",
                    "extra_options": ["Chipset", "Graphics Chip", "Video Card"],
                    "id": 4,
                    "options": ["Cpu.", "Ram", "Igpu"],
                    "options_algorithm": "sense2vec",
                    "question_statement": "What is the speed of the system clock within the processor?",
                    "question_type": "MCQ",
                },
                {
                    "answer": "disk",
                    "context": "The main device categories are: The main parts of a computer system are: Input devices These devices are used to get data into the computer system Processing devices These manipulate the data using to a set of instructions called a program Output devices These are used to get data out of a computer system Storage devices The can store the data for use at a later stage Communications devices These can send the data to another computer system 1 System Unit The container for the motherboard, disk drives etc. Below is shown typical power usage for a number of computer devices: • Motherboard: 60 watts • Processor: 90 watts • Memory: 10 watts/128MB • Processor fan: 5 watts • Graphics card: 40 watts • Hard disk: 25 watts • Optical drive: 30 watts As can be seen, a large power supply (at least 400 Watts) is preferable and does not use more energy as it only supplies power on demand. Examples include: • Motherboard • Hard disk • RAM • Power supply • Processor • Case • Monitor • Keyboard • Mouse Software: The term software is used to describe computer programs that perform a task or tasks on a computer system.",
                    "extra_options": [],
                    "id": 5,
                    "options": ["Hard Drive", "Boot Sector"],
                    "options_algorithm": "sense2vec",
                    "question_statement": "What is the main component of a computer system?",
                    "question_type": "MCQ",
                },
            ],
            "statement": "Hardware and Software A computer system is made up of a combination of hardware and software. Hardware: All of the electronic and mechanical equipment in a computer is called the hardware. Examples include: • Motherboard • Hard disk • RAM • Power supply • Processor • Case • Monitor • Keyboard • Mouse Software: The term software is used to describe computer programs that perform a task or tasks on a computer system. Software can be grouped as follows: • System software: These are the programs that control the operation of the computer system. Operating systems and utility programs are the most common. The Operating System starts the computer, provides a user interface, manages the computer memory, manages storage, manages security and provides networking",
            "time_taken": 167.42159605026245,
        }
    }

    # Convert content to JSON string
    content_json = json.dumps(content)

    # Create a new Quiz object
    quiz = Quiz(
        content=content,
        pdf_file=pdf_file.filename,
        questions_number=questions_number,
        questions_type=questions_type,
        shared=False,
    #    user_id=current_user.id,
    )

    # db.session.add(quiz)
    # db.session.commit()

    # Save the quiz to the database

    # Return success response
    return (
        jsonify(
            {
                "message": "Quiz created successfully!",
                "Quiz": content,
                "Quiz_pdf": "dawnload_link for the pdf",
            }
        ),
       
    )


@app.route("/api/v1/login", methods=["POST"])
def login():
    auth = request.get_json()
    if not auth or not auth["username"] or not auth["password"]:
        return jsonify({"message": "Please provide username and password!"})
    user = User.query.filter_by(username=auth["username"]).first()
   
    if not user:
        return jsonify({"message": "Could not verify user!not found"})
    if check_password_hash(user.password, auth["password"]):
        token = jwt.encode(
            {
                "public_id": user.public_id,
                "exp": datetime.utcnow() + timedelta(minutes=30),
            },
            app.config["SECRET_KEY"],
        )
        return jsonify({"token": token})
    return jsonify({"message": "Could not verify user!"})


@app.route("/api/v1/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or not data["username"] or not data["password"]:
        return jsonify({"message": "Please provide username and password!"})
    hashed_password = generate_password_hash(data["password"], method="pbkdf2:sha256")
    new_user = User(
        public_id=str(uuid.uuid4()),
        username=data["username"],
        email=data["email"],
        password=hashed_password,
        admin=False,
        activated=True,
    )
    db.session.add(new_user)
    db.session.commit()

    user_data = {
        "public_id": new_user.public_id,
        "username": new_user.username,
        "email": new_user.email,
    }
    return jsonify({"message": "User created successfully", "user": user_data})


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True, port=8080)
