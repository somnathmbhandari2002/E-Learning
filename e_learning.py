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
from bson import ObjectId
from typing import List
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

app = FastAPI()

#MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["elearning_db"]

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

# Register User with Role as Dropdown using Enum
@app.post("/register")
async def register(
    name: str = Form(...),
    email: str = Form(...),
    role: Role = Form(...),  # Use Form for the role (not Query)
):
    existing_user = db.users.find_one({"email": email})
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

    db.users.insert_one({"name": name, "email": email, "password": hashed_password, "role": role, "student_id": student_id, "instructor_id": instructor_id})
    
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
    db_user = db.users.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check for instructor login key
    if db_user["role"] == "instructor" and password != "somnath":
        raise HTTPException(status_code=401, detail="Invalid instructor login key")
    
    # Check for user password
    if not bcrypt.checkpw(password.encode('utf-8'), db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT token
    token = jwt.encode({"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)}, SECRET_KEY, algorithm="HS256")

    # Send email to the user upon successful login
    subject = "Login Successful"
    content = f"Dear {db_user['name']},<br>Your login was successful. Welcome back to the E-learning platform!<br>Your ID: {db_user['student_id'] if db_user['role'] == 'student' else db_user['instructor_id']}"
    await send_email(subject, email, content)

    # Return success message with token and role
    return {"message": "Login successful", "role": db_user["role"], "user_id": db_user['student_id'] if db_user['role'] == 'student' else db_user['instructor_id']}

# Login
@app.post("/instructor-login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
    instructor_key: str = Form(None),  # Optional field for instructor login key
):
    db_user = db.users.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check for instructor login key if the user is an instructor
    if db_user["role"] == "instructor":
        # Default instructor login key is 'somnath'
        if instructor_key != "somnath":
            raise HTTPException(status_code=401, detail="Invalid instructor login key")
        
        # Verify the autogenerated password (hashed password)
        if not bcrypt.checkpw(password.encode('utf-8'), db_user["password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    else:
        # For non-instructor users, just verify the password
        if not bcrypt.checkpw(password.encode('utf-8'), db_user["password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT token
    token = jwt.encode(
        {"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)},
        SECRET_KEY,
        algorithm="HS256"
    )

    # Send email to the user upon successful login
    subject = "Login Successful"
    content = f"Dear {db_user['name']},<br>Your login was successful. Welcome back to the E-learning platform!"
    await send_email(subject, email, content)

    # Return success message with token and role
    return {"message": "Login successful"}


# Forgot Password Endpoint
@app.post("/forgot-password")
async def forgot_password(email: str = Form(...)):
    db_user = db.users.find_one({"email": email})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = generate_numeric_otp()  # Generate a 6-digit numeric OTP
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    db.otp.insert_one({"email": email, "otp": otp, "expiration_time": expiration_time})

    subject = "Password Reset OTP"
    content = f"Dear User,<br> Your OTP for password reset is: {otp}. This OTP is valid for 10 minutes."

    await send_email(subject, email, content)

    return {"message": "OTP sent to your email"}

# Reset Password
@app.post("/reset-password")
async def reset_password(
    email: str = Form(...),
    otp: str = Form(...),
    new_password: str = Form(...),
):
    otp_record = db.otp.find_one({"email": email, "otp": otp})
    if not otp_record:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    if otp_record["expiration_time"] < datetime.datetime.utcnow():
        raise HTTPException(status_code=400, detail="OTP has expired")

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    db.users.update_one({"email": email}, {"$set": {"password": hashed_password}})
    db.otp.delete_many({"email": email})  # Remove OTP after successful password reset

    subject = "Password Reset Confirmation"
    content = f"Dear User,<br> Your password has been successfully reset."

    await send_email(subject, email, content)

    return {"message": "Password reset successfully"}

@app.get("/student-view-course")
async def student_view_course(student_id: str, subject_name: str):
    # Validate student
    student = db.users.find_one({"student_id": student_id})
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


from gridfs import GridFS
fs = GridFS(db)

# Course Schema
class Course(BaseModel):
    course_name: str
    subject_name: str
    instructor_id: str
    subject_id: str = None  # Auto-generated subject ID
    videos: List[str] = []  # List of video file URLs
    pdfs: List[str] = []  # List of PDF file URLs
    created_date: datetime.datetime

# Helper function to generate unique subject ID
def generate_unique_subject_id():
    return str(ObjectId())[:8].upper()  # Short unique ID

@app.post("/courses")
async def add_course(
    course_name: str = Form(...),
    subject_name: str = Form(...),
    lesson_name: str = Form(...),  # Added lesson_name
    instructor_id: str = Form(...),
    videos: List[UploadFile] = File(...),
    pdfs: List[UploadFile] = File(...),
):
    # Validate instructor
    instructor = db.users.find_one({"instructor_id": instructor_id})
    if not instructor or instructor["role"] != "instructor":
        raise HTTPException(status_code=401, detail="Invalid instructor ID")

    # Generate unique subject_id
    subject_id = generate_unique_subject_id()

    # Store videos and PDFs in MongoDB as binary
    video_files = []
    pdf_files = []

    for video in videos:
        video_content = Binary(video.file.read())  # Convert to Binary
        video_files.append({"filename": video.filename, "content": video_content, "content_type": video.content_type})

    for pdf in pdfs:
        pdf_content = Binary(pdf.file.read())  # Convert to Binary
        pdf_files.append({"filename": pdf.filename, "content": pdf_content, "content_type": pdf.content_type})

    # Create the course document with lesson name
    course = {
        "course_name": course_name,
        "subject_name": subject_name,
        "lesson_name": lesson_name,  # Added lesson name
        "instructor_id": instructor_id,
        "subject_id": subject_id,
        "videos": video_files,  # Store binary video data
        "pdfs": pdf_files,  # Store binary PDF data
        "created_date": datetime.datetime.utcnow(),
    }

    # Insert course into the database
    db.courses.insert_one(course)

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

@app.get("/course/media/{course_name}/{subject_name}/{lesson_name}")
async def fetch_media(course_name: str, subject_name: str, lesson_name: str):
    # Find the course with matching course_name, subject_name, and lesson_name
    course = db.courses.find_one(
        {"course_name": course_name, "subject_name": subject_name, "lesson_name": lesson_name}
    )

    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Get videos and PDFs
    videos = course.get("videos", [])
    pdfs = course.get("pdfs", [])

    if not videos and not pdfs:
        raise HTTPException(status_code=404, detail="No video or PDF found for the given lesson")

    # Prepare the zip file to include both video and PDF
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        # If videos exist, add them to the zip file
        for video in videos:
            if isinstance(video, dict):  # Ensure video is a dictionary
                video_content = video.get("content")
                video_filename = f"{lesson_name}.mp4"  # Use lesson name as filename or customize as needed
                zip_file.writestr(video_filename, video_content)

        # If PDFs exist, add them to the zip file
        for pdf in pdfs:
            if isinstance(pdf, dict):  # Ensure PDF is a dictionary
                pdf_content = pdf.get("content")
                pdf_filename = f"{lesson_name}.pdf"  # Use lesson name as filename or customize as needed
                zip_file.writestr(pdf_filename, pdf_content)

    # Reset the buffer position to the beginning before sending
    zip_buffer.seek(0)

    # Return the zip file containing both video and PDF
    return StreamingResponse(zip_buffer, media_type="application/zip", headers={"Content-Disposition": "attachment; filename=media.zip"})


# Retrieve and stream a specific video from MongoDB
@app.get("/course/video/{course_name}/{subject_name}/{lesson_name}")
async def stream_video(course_name: str, subject_name: str, lesson_name: str):
    # Find course with matching course_name, subject_name, and lesson_name
    course = db.courses.find_one(
        {"course_name": course_name, "subject_name": subject_name, "lesson_name": lesson_name}
    )
    
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    videos = course.get("videos", [])  # Get videos list safely
    if not isinstance(videos, list):
        raise HTTPException(status_code=500, detail="Invalid video data format")

    if not videos:
        raise HTTPException(status_code=404, detail="No videos available for this lesson")

    # Return the first video found (Modify if you need multiple videos)
    for video in videos:
        if isinstance(video, dict):  # Ensure video is a dictionary
            return StreamingResponse(iter([video["content"]]), media_type=video["content_type"])

    raise HTTPException(status_code=404, detail="Video not found for the given lesson")


# Retrieve all course PDFs by course_name and subject_name
@app.get("/course/pdfs")
async def get_course_pdfs(course_name: str, subject_name: str):
    course = db.courses.find_one({"course_name": course_name, "subject_name": subject_name})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    if not course.get("pdfs"):
        raise HTTPException(status_code=404, detail="No PDFs available for this course")

    # Return a list of PDF filenames
    return {"pdfs": [pdf["filename"] for pdf in course["pdfs"]]}



from typing import Optional
# Retrieve all course videos across all courses and subjects
@app.get("/course/videos")
async def get_all_course_videos(course_name: Optional[str] = None, subject_name: Optional[str] = None):
    # Retrieve all courses that contain videos
    courses = db.courses.find({"videos": {"$exists": True, "$ne": []}})
    videos = []
    
    for course in courses:
        if isinstance(course["videos"][0], str):  # If videos are stored as filenames (strings)
            videos.extend(course["videos"])
        else:  # If videos are stored as dictionaries with metadata
            videos.extend([video["filename"] for video in course["videos"]])

    if not videos:
        raise HTTPException(status_code=404, detail="No videos available")

    return {"videos": videos}

# Retrieve all course PDFs across all courses and subjects
@app.get("/course/pdfs")
async def get_all_course_pdfs(course_name: Optional[str] = None, subject_name: Optional[str] = None):
    # Retrieve all courses that contain PDFs
    courses = db.courses.find({"pdfs": {"$exists": True, "$ne": []}})
    pdfs = []

    for course in courses:
        pdfs.extend([pdf["filename"] for pdf in course["pdfs"]])

    if not pdfs:
        raise HTTPException(status_code=404, detail="No PDFs available")

    return {"pdfs": pdfs}



# Retrieve and stream a specific PDF from MongoDB
@app.get("/course/pdf/{course_name}/{subject_name}/{lesson_name}")
async def stream_pdf(course_name: str, subject_name: str, lesson_name: str):
    # Find the course document with the given course_name, subject_name, and lesson_name
    course = db.courses.find_one(
        {"course_name": course_name, "subject_name": subject_name, "lesson_name": lesson_name}
    )

    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    pdfs = course.get("pdfs", [])  # Ensure 'pdfs' exists
    if not isinstance(pdfs, list):
        raise HTTPException(status_code=500, detail="Invalid PDF data format")

    if not pdfs:
        raise HTTPException(status_code=404, detail="No PDFs available for this lesson")

    # Return the first PDF found (Modify if multiple PDFs should be returned)
    for pdf in pdfs:
        if isinstance(pdf, dict):  # Ensure pdf is a dictionary
            return StreamingResponse(iter([pdf["content"]]), media_type=pdf["content_type"])

    raise HTTPException(status_code=404, detail="PDF not found for the given lesson")

# Edit Course (Instructor Only)
@app.put("/courses/{subject_id}")
async def edit_course(
    subject_id: str,
    course_name: str = Form(...),
    subject_name: str = Form(...),
    lesson_name: str = Form(...),  # Added lesson_name
    instructor_id: str = Form(...),
    videos: List[UploadFile] = File(...),
    pdfs: List[UploadFile] = File(...),
):
    # Validate instructor
    instructor = db.users.find_one({"instructor_id": instructor_id})
    if not instructor or instructor["role"] != "instructor":
        raise HTTPException(status_code=401, detail="Invalid instructor ID")

    # Find the existing course using subject_id
    course = db.courses.find_one({"subject_id": subject_id})
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")

    # Update the course details
    updated_course = {
        "course_name": course_name,
        "subject_name": subject_name,
        "lesson_name": lesson_name,
        "instructor_id": instructor_id,
        "subject_id": subject_id,
        "created_date": datetime.datetime.utcnow(),
    }

    # Store new videos and PDFs, update them in the course if uploaded
    video_files = []
    if videos:
        for video in videos:
            video_content = Binary(video.file.read())  # Convert to Binary
            video_files.append({"filename": video.filename, "content": video_content, "content_type": video.content_type})
        updated_course["videos"] = video_files  # Update video files

    pdf_files = []
    if pdfs:
        for pdf in pdfs:
            pdf_content = Binary(pdf.file.read())  # Convert to Binary
            pdf_files.append({"filename": pdf.filename, "content": pdf_content, "content_type": pdf.content_type})
        updated_course["pdfs"] = pdf_files  # Update PDF files

    # Update the course document in the database
    db.courses.update_one({"subject_id": subject_id}, {"$set": updated_course})

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
    db.feedback.insert_one({"name": name, "feedback": feedback})
    return {"message": "Feedback submitted"}

@app.get("/")
def home():
    return {"message": "E-learning API is running"}
