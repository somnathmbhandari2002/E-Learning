from fastapi import FastAPI, HTTPException, Form, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel
from enum import Enum
import jwt
import bcrypt
import datetime
import random
import string
from fastapi.responses import StreamingResponse
from bson import ObjectId, Binary
from typing import List
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
from pydantic import BaseModel
from typing import List, Dict
import uuid
from fastapi.middleware.cors import CORSMiddleware
from PIL import Image, ImageDraw, ImageFont
from datetime import datetime, timedelta

import io
import os

app = FastAPI()

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["elearning_db"]
users_collection = db["users"]
courses_collection = db["courses"]
feedback_collection = db["feedback"]
otp_collection = db["otp"]
questions_collection = db["questions"]
results_collection = db["results"]  # Store quiz results
certificates_collection = db["certificates"]

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

# Email Configuration
conf = ConnectionConfig(
    MAIL_USERNAME="snipetech.upl@gmail.com",
    MAIL_PASSWORD="ldqc wnak cdwl ozzh",
    MAIL_FROM="snipetech.upl@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)
fm = FastMail(conf)

# Enable CORS (for frontend to connect)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# User Schema
class User(BaseModel):
    name: str
    email: str
    password: str
    role: str  # student | instructor
    student_id: str = None  # Added field for student ID
    instructor_id: str = None  # Added field for instructor ID

# Generate Unique ID
def generate_unique_id(role: str):
    """Generates a unique ID for student or instructor."""
    id_prefix = "SID-" if role == "student" else "INSTID-"
    unique_id = id_prefix + ''.join(random.choices(string.digits, k=8))  # 8-digit ID
    return unique_id

# Course Schema
class Course(BaseModel):
    title: str
    description: str
    instructor: str
    videos: list
    pdfs: list

# Generate Random Password
def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

# Generate 6-digit numeric OTP
def generate_numeric_otp(length=6):
    otp = ''.join(random.choice(string.digits) for _ in range(length))
    return otp

# Send Email
async def send_email(subject: str, recipient_email: str, content: str):
    message = MessageSchema(
        subject=subject,
        recipients=[recipient_email],
        body=content,
        subtype="html"
    )
    try:
        await fm.send_message(message)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email failed to send: {str(e)}")


# Enum for User Roles
class Role(str, Enum):
    student = "student"
    instructor = "instructor"

@app.post("/register")
async def register(
    name: str = Form(...),
    email: str = Form(...),
    role: Role = Form(...),  # Use Form for the role (not Query)
):
    existing_user = users_collection.find_one({"email": email})  # ✅ Corrected reference
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    password = generate_password()  # Generate a random 8-digit alphanumeric password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    student_id = None
    instructor_id = None

    if role == Role.student:
        student_id = generate_unique_id("student")
    else:
        instructor_id = generate_unique_id("instructor")

    users_collection.insert_one({  # ✅ Corrected reference
        "name": name,
        "email": email,
        "password": hashed_password,
        "role": role.value,  # ✅ Convert Enum to string
        "student_id": student_id,
        "instructor_id": instructor_id
    })

    subject = "Your Registration Details"
    if role == Role.student:
        content = f"Dear {name},<br> Welcome to the E-learning platform. Your login credentials are:<br>Email: {email}<br>Password: {password}<br>Your Student ID: {student_id}"
    else:
        content = f"Dear Instructor {name},<br> Welcome to the E-learning platform. Your login credentials are:<br>Email: {email}<br>Password: {password}<br>Your Instructor ID: {instructor_id}"

    await send_email(subject, email, content)
    
    return {"message": "User registered successfully, check your email for login details"}



# Login
@app.post("/login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
):
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check for instructor login key
    if db_user["role"] == "instructor" and password != "somnath":
        raise HTTPException(status_code=401, detail="Invalid instructor login key")
    
    # Check for user password
    if not bcrypt.checkpw(password.encode('utf-8'), db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT token (without expiration time)
    token = jwt.encode({"email": email}, SECRET_KEY, algorithm="HS256")

    # Send email to the user upon successful login
    subject = "Login Successful"
    content = f"Dear {db_user['name']},<br>Your login was successful. Welcome back to the E-learning platform!<br>Your ID: {db_user['student_id'] if db_user['role'] == 'student' else db_user['instructor_id']}"
    await send_email(subject, email, content)

    # Return success message with token and role
    return {"message": "Login successful", "role": db_user["role"], "user_id": db_user['student_id'] if db_user['role'] == 'student' else db_user['instructor_id']}

# Instructor Login
@app.post("/instructor-login")
async def instructor_login(
    email: str = Form(...),
    password: str = Form(...),
    instructor_key: str = Form(None),  
):
    db_user = users_collection.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check for instructor login key if the user is an instructor
    if db_user["role"] == "instructor":
        if instructor_key != "somnath":
            raise HTTPException(status_code=401, detail="Invalid instructor login key")
        
        # Verify the password
        if not bcrypt.checkpw(password.encode('utf-8'), db_user["password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    else:
        # For non-instructor users, just verify the password
        if not bcrypt.checkpw(password.encode('utf-8'), db_user["password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT token (without expiration time)
    token = jwt.encode({"email": email}, SECRET_KEY, algorithm="HS256")

    # Send email to the user upon successful login
    subject = "Login Successful"
    content = f"Dear {db_user['name']},<br>Your login was successful. Welcome back to the E-learning platform!"
    await send_email(subject, email, content)

    # Return success message with token and role
    return {"message": "Login successful"}



# Forgot Password Endpoint
@app.post("/forgot-password")
async def forgot_password(email: str = Form(...)):
    db_user = users_collection.find_one({"email": email})  # ✅ Corrected reference
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = generate_numeric_otp()  # Generate a 6-digit numeric OTP
    otp_collection.insert_one({"email": email, "otp": otp})  # Removed expiration_time

    subject = "Password Reset OTP"
    content = f"Dear User,<br> Your OTP for password reset is: {otp}. This OTP is valid for use."

    await send_email(subject, email, content)

    return {"message": "OTP sent to your email"}

# Reset Password
@app.post("/reset-password")
async def reset_password(
    email: str = Form(...),
    otp: str = Form(...),
    new_password: str = Form(...),
):
    otp_record = otp_collection.find_one({"email": email, "otp": otp})  # ✅ Corrected reference
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
    otp_collection.delete_many({"email": email})  # ✅ Remove OTP after reset

    subject = "Password Reset Confirmation"
    content = f"Dear User,<br> Your password has been successfully reset."

    await send_email(subject, email, content)

    return {"message": "Password reset successfully"}


@app.get("/student-view-course") 
async def student_view_course(student_id: str, subject_name: str):
    # Validate student
    student = users_collection.find_one({"student_id": student_id})  # Corrected reference
    if not student or student["role"] != "student":
        raise HTTPException(status_code=401, detail="Invalid student ID")

    # Find the course by subject name
    course = db.courses.find_one({"subject_name": subject_name})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Convert ObjectId to string before returning the response
    course = convert_objectid_to_str(course)

    # Return the course details (videos and PDFs)
    return {
        "subject_name": course["subject_name"],
        "videos": course["videos"],
        "pdfs": course["pdfs"]
    }

# Helper function to generate unique subject ID
def generate_unique_subject_id():
    return str(ObjectId())[:8].upper()  # Short unique ID (first 8 characters of ObjectId)


import gridfs

# MongoDB Connection
# client = MongoClient("mongodb://localhost:27017/")
db = client["elearning_db"]
users_collection = db["users"]
courses_collection = db["courses"]
fs = gridfs.GridFS(db)  # Initialize GridFS

def generate_unique_subject_id():
    return f"SUBJ-{courses_collection.count_documents({}) + 1:06d}"

@app.post("/inst-add-courses")
async def add_course(
    course_name: str = Form(...),
    subject_name: str = Form(...),
    lesson_name: str = Form(...),
    instructor_id: str = Form(...),
    videos: List[UploadFile] = File(...),
    pdfs: List[UploadFile] = File(...),
):
    # Validate instructor (Use the correct field name)
    instructor = users_collection.find_one({"instructor_id": instructor_id})  
    if not instructor or instructor.get("role") != "instructor":
        raise HTTPException(status_code=401, detail=f"Invalid instructor ID: {instructor_id}. Please verify the ID.")

    # Generate unique subject_id
    subject_id = generate_unique_subject_id()

    # Store videos and PDFs in GridFS
    video_files = []
    pdf_files = []

    for video in videos:
        video_content = await video.read()
        video_id = fs.put(video_content, filename=video.filename, content_type=video.content_type)
        video_files.append({"filename": video.filename, "gridfs_id": str(video_id)})

    for pdf in pdfs:
        pdf_content = await pdf.read()
        pdf_id = fs.put(pdf_content, filename=pdf.filename, content_type=pdf.content_type)
        pdf_files.append({"filename": pdf.filename, "gridfs_id": str(pdf_id)})

    # Create the course document
    course = {
        "course_name": course_name,
        "subject_name": subject_name,
        "lesson_name": lesson_name,
        "instructor_id": instructor_id,
        "subject_id": subject_id,
        "videos": video_files,
        "pdfs": pdf_files,
    }

    # Insert course into the database
    courses_collection.insert_one(course)

    return {"message": "Course added successfully", "subject_id": subject_id}

# Retrieve all course videos by course_name and subject_name
@app.get("/course/videos")
async def get_course_videos(course_name: str, subject_name: str):
    course = db.courses.find_one({"course_name": course_name, "subject_name": subject_name})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    if not course.get("videos"):
        raise HTTPException(status_code=404, detail="No videos available for this course")

    # Check if videos are stored as ObjectIds or dictionaries
    if isinstance(course["videos"][0], str):  # If stored as ObjectIds (strings)
        return {"videos": course["videos"]}
    else:  # If stored as dictionaries with metadata
        return {"videos": [video["filename"] for video in course["videos"]]}
    
from io import BytesIO
import zipfile
import gridfs

fs = gridfs.GridFS(db)  # Initialize GridFS
@app.get("/course/media/{course_name}/{subject_name}/{lesson_name}")
async def fetch_media(course_name: str, subject_name: str, lesson_name: str):
    # Find the course with matching course_name, subject_name, and lesson_name
    course = courses_collection.find_one(
        {"course_name": course_name, "subject_name": subject_name, "lesson_name": lesson_name}
    )

    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    videos = course.get("videos", [])
    pdfs = course.get("pdfs", [])

    if not videos and not pdfs:
        raise HTTPException(status_code=404, detail="No video or PDF found for the given lesson")

    # Prepare the zip file
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        # Retrieve videos from GridFS
        for video in videos:
            if isinstance(video, dict):
                gridfs_id = video.get("gridfs_id")
                if gridfs_id:
                    try:
                        video_file = fs.get(gridfs_id)
                        video_content = video_file.read()
                        zip_file.writestr(video["filename"], video_content)
                    except gridfs.errors.NoFile:
                        print(f"GridFS file with ID {gridfs_id} not found.")

        # Retrieve PDFs from GridFS
        for pdf in pdfs:
            if isinstance(pdf, dict):
                gridfs_id = pdf.get("gridfs_id")
                if gridfs_id:
                    try:
                        pdf_file = fs.get(gridfs_id)
                        pdf_content = pdf_file.read()
                        zip_file.writestr(pdf["filename"], pdf_content)
                    except gridfs.errors.NoFile:
                        print(f"GridFS file with ID {gridfs_id} not found.")

    zip_buffer.seek(0)

    return StreamingResponse(zip_buffer, media_type="application/zip", headers={"Content-Disposition": "attachment; filename=media.zip"})


# from fastapi import FastAPI, HTTPException
# from fastapi.responses import StreamingResponse
# import gridfs
# from pymongo import MongoClient
# from bson import ObjectId


client = MongoClient()
db = client["elearning_db"]
fs = gridfs.GridFS(db)
courses_collection = db["courses"]

@app.get("/course/video/{course_name}/{subject_name}/{lesson_name}")
async def stream_video(course_name: str, subject_name: str, lesson_name: str):
    course = courses_collection.find_one(
        {"course_name": course_name, "subject_name": subject_name, "lesson_name": lesson_name}
    )

    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    videos = course.get("videos", [])
    if not videos:
        raise HTTPException(status_code=404, detail="No videos available for this lesson")

    print(f"Found videos: {videos}")

    for video in videos:
        if isinstance(video, dict):
            gridfs_id = video.get("gridfs_id")
            if gridfs_id:
                try:
                    video_file = fs.get(ObjectId(gridfs_id))

                    def iterfile():
                        while chunk := video_file.read(8192):
                            yield chunk
                    
                    return StreamingResponse(iterfile(), media_type=video_file.content_type)

                except gridfs.errors.NoFile:
                    print(f"GridFS file with ID {gridfs_id} not found.")
                    continue  # Continue checking the next video

    raise HTTPException(status_code=404, detail="Video file not found in GridFS. Please re-upload the video.")


from typing import Optional



@app.get("/course/pdfs")
async def get_all_course_pdfs(course_name: Optional[str] = None, subject_name: Optional[str] = None):
    """
    Retrieve all PDFs based on optional Course and Subject filtering.
    """
    query = {"pdfs": {"$exists": True, "$ne": []}}
    
    if course_name:
        query["course_name"] = {"$regex": f"^{course_name}$", "$options": "i"}
    if subject_name:
        query["subject_name"] = {"$regex": f"^{subject_name}$", "$options": "i"}

    courses = db.courses.find(query)
    pdfs = []

    for course in courses:
        for pdf in course["pdfs"]:
            pdfs.append({
                "filename": pdf["filename"],
                "preview_url": f"http://localhost:8000/view/{pdf['filename']}",
                "download_url": f"http://localhost:8000/download/{pdf['filename']}"
            })

    if not pdfs:
        raise HTTPException(status_code=404, detail="No PDFs available")

    return {"pdfs": pdfs}

import gridfs
from io import BytesIO
fs = gridfs.GridFS(db)  # GridFS for file storage


@app.get("/view/{filename}")
async def view_pdf(filename: str):
    """
    Stream PDF directly from MongoDB for preview.
    """
    pdf_file = fs.find_one({"filename": filename})
    if not pdf_file:
        raise HTTPException(status_code=404, detail="PDF not found in database")

    return StreamingResponse(BytesIO(pdf_file.read()), media_type="application/pdf")


@app.get("/download/{filename}")
async def download_pdf(filename: str):
    """
    Stream PDF directly from MongoDB for download.
    """
    pdf_file = fs.find_one({"filename": filename})
    if not pdf_file:
        raise HTTPException(status_code=404, detail="PDF not found in database")

    return StreamingResponse(
        BytesIO(pdf_file.read()), 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )



# Retrieve and stream a specific PDF from MongoDB
@app.get("/course/pdf/{course_name}/{subject_name}/{lesson_name}")
async def stream_pdf(course_name: str, subject_name: str, lesson_name: str):
    """Stream PDF file for a given course lesson"""
    # Find course
    course = courses_collection.find_one(
        {"course_name": course_name, "subject_name": subject_name, "lesson_name": lesson_name}
    )

    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    pdfs = course.get("pdfs", [])
    if not pdfs:
        raise HTTPException(status_code=404, detail="No PDFs available for this lesson")

    # Fetch the first available PDF
    for pdf in pdfs:
        if isinstance(pdf, dict):
            gridfs_id = pdf.get("gridfs_id")
            filename = pdf.get("filename", "document.pdf")  # Default filename

            if gridfs_id:
                try:
                    pdf_file = fs.get(ObjectId(gridfs_id))  # Retrieve PDF from GridFS

                    def iterfile():
                        while chunk := pdf_file.read(8192):
                            yield chunk
                    
                    # Stream PDF with Content-Disposition for inline viewing & download
                    return StreamingResponse(
                        iterfile(),
                        media_type="application/pdf",
                        headers={"Content-Disposition": f'inline; filename="{filename}"'}
                    )

                except gridfs.errors.NoFile:
                    continue  # Try the next PDF if the file isn't found

    raise HTTPException(status_code=404, detail="PDF file not found in GridFS. Please re-upload the PDF.")


# Edit course
from gridfs import GridFS

# MongoDB Connection
# client = MongoClient("mongodb://localhost:27017")
db = client["elearning_db"]
users_collection = db["users"]
courses_collection = db["courses"]
fs = GridFS(db)

@app.put("/courses/{subject_id}")
async def edit_course(
    subject_id: str,
    course_name: str = Form(None),
    subject_name: str = Form(None),
    lesson_name: str = Form(None),
    instructor_id: str = Form(...),
    videos: List[UploadFile] = File(None),
    pdfs: List[UploadFile] = File(None),
):
    # Validate instructor
    instructor = users_collection.find_one({"instructor_id": instructor_id})
    if not instructor or instructor.get("role") != "instructor":
        raise HTTPException(status_code=401, detail="Invalid instructor ID")

    # Find the existing course using subject_id
    course = courses_collection.find_one({"subject_id": subject_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Prepare updated data
    update_data = {}
    if course_name:
        update_data["course_name"] = course_name
    if subject_name:
        update_data["subject_name"] = subject_name
    if lesson_name:
        update_data["lesson_name"] = lesson_name

    # Store new videos in GridFS (if uploaded)
    if videos:
        video_files = []
        for video in videos:
            video_content = await video.read()
            video_id = fs.put(video_content, filename=video.filename, content_type=video.content_type)
            video_files.append({"filename": video.filename, "gridfs_id": str(video_id)})
        update_data["videos"] = video_files  # Update video files

    # Store new PDFs in GridFS (if uploaded)
    if pdfs:
        pdf_files = []
        for pdf in pdfs:
            pdf_content = await pdf.read()
            pdf_id = fs.put(pdf_content, filename=pdf.filename, content_type=pdf.content_type)
            pdf_files.append({"filename": pdf.filename, "gridfs_id": str(pdf_id)})
        update_data["pdfs"] = pdf_files  # Update PDF files

    # Update the course document in the database
    # update_data["updated_at"] = datetime.datetime.utcnow()
    # courses_collection.update_one({"subject_id": subject_id}, {"$set": update_data})

    return {"message": "Course updated successfully", "subject_id": subject_id}

# Convert ObjectId to string
def convert_objectid_to_str(course):
    if '_id' in course:
        course['_id'] = str(course['_id'])  # Convert the ObjectId to a string
    return course

# Get Course by Subject ID
@app.get("/courses/{subject_id}")
def get_course(subject_id: str):
    course = db.courses.find_one({"subject_id": subject_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    
    # Convert ObjectId to string before returning the response
    course = convert_objectid_to_str(course)

    return {"course": course}




# Submit Feedback
@app.post("/feedback")
def submit_feedback(name: str = Form(...), feedback: str = Form(...)):
    feedback_collection.insert_one({"name": name, "feedback": feedback})
    return {"message": "Feedback submitted"}

#------------------------------------------------------------------------------------




app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Question(BaseModel):
    instid: str
    course_name: str
    lesson_name: str
    qno: int
    question: str
    options: List[str]
    correct_answer: str

@app.post("/add_questions/")
async def add_questions(questions: List[Question]) -> dict:  # Accepting a list of questions
    question_entries = [
        {"question_id": str(uuid.uuid4()), **question.dict()}
        for question in questions
    ]

    try:
        result = questions_collection.insert_many(question_entries)
        return {"message": f"{len(question_entries)} questions added successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to add questions")

@app.get("/get_quiz/")
async def get_quiz(course_name: str, lesson_name: str) -> dict:
    questions = list(questions_collection.find(
        {"course_name": course_name, "lesson_name": lesson_name},
        {"_id": 0}
    ))
    
    if not questions:
        raise HTTPException(status_code=404, detail="No questions found")
    
    return {"questions": questions}

class QuizEvaluation(BaseModel):
    user_name: str
    course_name: str
    lesson_name: str
    answers: Dict[str, str]  # Answers in {"question_id": "selected_answer"} format

# from pydantic import BaseModel
# from bson import ObjectId

# Custom response model to handle ObjectId serialization
class QuizResult(BaseModel):
    user_name: str
    course_name: str
    lesson_name: str
    score: int
    total_questions: int
    total_marks: int
    answered_questions: int
    percentage: float

    # This will convert ObjectId to string if present
    class Config:
        json_encoders = {
            ObjectId: str
        }

@app.post("/evaluate_quiz/")
async def evaluate_quiz(evaluation: QuizEvaluation) -> dict:
    questions = list(questions_collection.find(
        {"course_name": evaluation.course_name, "lesson_name": evaluation.lesson_name},
        {"_id": 0, "question_id": 1, "correct_answer": 1}
    ))

    if not questions:
        raise HTTPException(status_code=404, detail="No questions found for this lesson")

    total_questions = len(questions)
    correct_answers = 0
    answered_questions = len(evaluation.answers)

    print("User Answers:", evaluation.answers)  # Debugging
    print("Correct Answers:", {q["question_id"]: q["correct_answer"] for q in questions})  # Debugging

    for question in questions:
        qid = question["question_id"]
        if qid in evaluation.answers:
            user_answer = evaluation.answers[qid].strip().lower()
            correct_answer = question["correct_answer"].strip().lower()
            print(f"QID: {qid} | User: {user_answer} | Correct: {correct_answer}")  # Debugging
            if user_answer == correct_answer:
                correct_answers += 1

    percentage = (correct_answers / total_questions) * 100 if total_questions else 0

    result_data = {
        "user_name": evaluation.user_name,
        "course_name": evaluation.course_name,
        "lesson_name": evaluation.lesson_name,
        "score": correct_answers,
        "total_questions": total_questions,
        "total_marks": total_questions,
        "answered_questions": answered_questions,
        "percentage": percentage
    }

    # Insert into MongoDB
    try:
        results_collection.insert_one(result_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to store result")

    return QuizResult(**result_data).dict()

from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

# Serve static files for certificates
app.mount("/generated_certificates", StaticFiles(directory="E:/College project/frontend/generated_certificates"), name="generated_certificates")

# Paths to your template and font
CERTIFICATE_TEMPLATE_PATH = "E:/College project/backend/templates/certificate_template.jpg"
FONT_PATH = "c:/WINDOWS/Fonts/OLDENGL.TTF"
CERTIFICATE_SAVE_PATH = "E:/College project/frontend/generated_certificates"

class CertificateRequest(BaseModel):
    user_name: str

@app.post("/generate_certificate/")
async def generate_certificate(request: CertificateRequest):
    """Generate a certificate with the candidate's name and return the file path."""
    
    user_name = request.user_name.strip()

    if not os.path.exists(CERTIFICATE_TEMPLATE_PATH):
        raise HTTPException(status_code=500, detail="Certificate template not found")
    
    if not os.path.exists(FONT_PATH):
        raise HTTPException(status_code=500, detail="Font file not found")

    if not os.path.exists(CERTIFICATE_SAVE_PATH):
        os.makedirs(CERTIFICATE_SAVE_PATH)  # Create directory if not exists

    try:
        # Open the certificate template image
        img = Image.open(CERTIFICATE_TEMPLATE_PATH)
        draw = ImageDraw.Draw(img)
        font_size = 80
        
        # Load the font
        try:
            font = ImageFont.truetype(FONT_PATH, font_size)
        except OSError:
            font = ImageFont.load_default()

        # Calculate text width and height using textbbox()
        bbox = draw.textbbox((0, 0), user_name, font=font)
        text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]

        # Position the text at the center
        text_position = ((img.width - text_width) // 2, (img.height - text_height) // 2 - 50)
        
        # Draw the name on the certificate
        draw.text(text_position, user_name, fill="black", font=font)

        # Save the certificate
        certificate_filename = f"{user_name.replace(' ', '_')}.jpg"
        certificate_file_path = os.path.join(CERTIFICATE_SAVE_PATH, certificate_filename)
        img.save(certificate_file_path, format="JPEG")

        # Return the relative file path
        relative_path = f"generated_certificates/{certificate_filename}"
        return JSONResponse(content={"file_path": relative_path})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating certificate: {str(e)}")
    
import wikipedia

# ✅ Allow frontend to communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow requests from all domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from datetime import datetime

@app.get("/get_answer")
async def get_answer(query: str = Query(..., description="User's voice query")):
    """
    Fetch answers from Wikipedia or Google.
    """
    print(f"Received query: {query}")  # ✅ Log query to debug

    try:
        answer = wikipedia.summary(query, sentences=2)
    except wikipedia.exceptions.DisambiguationError as e:
        answer = f"Multiple results found: {', '.join(e.options[:5])}"
    except wikipedia.exceptions.PageError:
        answer = "No relevant Wikipedia page found. Searching Google..."
        google_url = f"https://www.google.com/search?q={query}"
        answer += f"\nCheck Google: {google_url}"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

    print(f"Returning answer: {answer}")  # ✅ Log answer for debugging
    return {"answer": answer}


# Pydantic model for the assignment given by the instructor
class Assignment(BaseModel):
    instructor_id: str
    course_name: str
    subject_name: str
    lesson_name: str
    questions: List[str]  # List of questions in the assignment
    created_at: datetime = datetime.now()

# Mock MongoDB database
db = {
    'instructor_assignment': []  # Initialize the collection with an empty list
}

@app.post("/instructor/assignments")
async def create_assignment(assignment: Assignment):
    """
    Endpoint for instructors to create an assignment.
    The assignment is stored in the instructor_assignment collection.
    """
    # Ensure the 'instructor_assignment' key exists in the db
    if 'instructor_assignment' not in db:
        db['instructor_assignment'] = []

    # Save the assignment in the database (simulating MongoDB insert)
    db['instructor_assignment'].append(assignment.dict())
    
    return {"message": "Assignment created successfully", "assignment": assignment}

from fastapi import UploadFile, File
from pydantic import BaseModel


# Initialize the 'std_assignment' key in the db dictionary
db = {'std_assignment': []}

@app.post("/student/assignments")
async def submit_assignment(
    file: UploadFile = File(...),
    student_name: str = Form(...),
    course_name: str = Form(...),
    subject_name: str = Form(...),
    lesson_name: str = Form(...),
    submission_date: datetime = datetime.now()):
    """
    Endpoint for students to submit their assignments with an uploaded file.
    The assignment is stored in the std_assignment collection.
    """
    # Create the uploaded_assignments directory if it doesn't exist
    upload_directory = "uploaded_assignments"
    if not os.path.exists(upload_directory):
        os.makedirs(upload_directory)

    # Save the file (e.g., store it in a folder or database, here we simulate by saving to a dictionary)
    file_location = f"{upload_directory}/{file.filename}"
    with open(file_location, "wb") as f:
        f.write(await file.read())  # Saving the file to the specified location

    # Save the student's assignment metadata (e.g., name, course) in the database
    submission_data = {
        "student_name": student_name,
        "course_name": course_name,
        "subject_name": subject_name,
        "lesson_name": lesson_name,
        "submission_date": submission_date,
        "file_location": file_location
    }

    # Add the submission to the database
    db['std_assignment'].append(submission_data)

    return {"message": "Assignment submitted successfully", "file_location": file_location}



@app.get("/")
def home():
    return {"message": "E-learning API is running"}

