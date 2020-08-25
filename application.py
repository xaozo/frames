import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import googlemaps
import requests

from helpers import apology, login_required

UPLOAD_FOLDER = "/Users/ianpoey/Desktop/coding/project/static/uploads"
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'JPG', 'JPEG', 'png', 'PNG'}
GOOGLE_MAPS_API_URL = 'http://maps.googleapis.com/maps/api/geocode/json?'
API_KEY = "AIzaSyAZqKvc9j0YR3Vl7w2r2Nn80rkPtoAYato"

# Configure application
app = Flask(__name__, static_url_path='/static')

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///frames.db")


@app.route("/")
@login_required
def index():
    username = session["username"]
    rows = db.execute("SELECT image, title FROM images WHERE username = :username ORDER BY id DESC LIMIT 1",
                        username=username)

    # user has photos
    if rows:
        image = rows[0]['image']
        title = rows[0]['title']

        return render_template("index.html", username=username, image=image, title=title)

    # user does not have photos
    else:
        return render_template("index2.html", username=username)


@app.route("/gallery", methods=["GET", "POST"])
@login_required
def gallery():
    
    # view another user's profile from gallery
    if request.method == "POST":
        user_images = []
        user = request.form.get("user")
        info = db.execute("SELECT bio, occupation, region FROM users WHERE username = :username", username=user)

        # get user's photos
        rows = db.execute("SELECT * FROM images WHERE username = :username", username=user)
        for row in rows:
            user_images.append(row)

        length = len(user_images)
        return render_template("profile.html", username=user, user_images=user_images, length=length,
                                bio=info[0]['bio'], occupation=info[0]['occupation'], region=info[0]['region'])

    else:
        gallery_photos = []
        rows = db.execute("SELECT * FROM images ORDER BY id DESC LIMIT 100")
        for row in rows:
            gallery_photos.append(row)

        length = len(gallery_photos)
        return render_template("gallery.html", gallery_photos=gallery_photos, length=length)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        title = request.form.get("title")
        caption = request.form.get("caption")
        file = request.files['file']

        if file and allowed_file(file.filename):
            # handle no caption
            if not caption:
                caption = ""

            # save image
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # tag image path to user in database
            imagepath = "/static/uploads/" + filename
            db.execute("INSERT INTO images (username, image, title, caption) VALUES (:username, :image, :title, :caption)",
                        username=session["username"], image=imagepath, title=title, caption=caption)
            return redirect("/")
        
        else:
            return apology("Choose valid file type")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("upload.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    
    # see location of another user while viewing that profile
    if request.method == "POST":
        # get location from database
        username = request.form.get("user")
        rows = db.execute("SELECT location FROM users WHERE username = :username ORDER BY id DESC", username=username)
        loc = rows[0]['location']
        
        # handle no location
        if not loc:
            return render_template("map2.html", username=username)

        # get coordinates and address of another user using google maps API
        result = googlemaps.Client(key=API_KEY).geocode(loc)
        lat = result[0]["geometry"]["location"]["lat"]
        lng = result[0]["geometry"]["location"]["lng"]
        address = result[0]["formatted_address"]

        return render_template("map.html", username=username, lat=lat, lng=lng, address=address)

    else:
        user_images = []
        username = session['username']

        # get user's information
        info = db.execute("SELECT bio, occupation, region FROM users WHERE username = :username ORDER BY id DESC", username=username)

        # get user's photos
        rows = db.execute("SELECT * FROM images WHERE username = :username", username=username)
        for row in rows:
            user_images.append(row)

        length = len(user_images)
        return render_template("profile.html", username=username, user_images=user_images, length=length,
                                bio=info[0]['bio'], occupation=info[0]['occupation'], region=info[0]['region'])


# implement an "edit profile" function
@app.route("/editprofile", methods=["GET", "POST"])
@login_required
def editprofile():
    
    username = session["username"]

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        bio = request.form.get("bio")
        occupation = request.form.get("occupation")
        location = request.form.get("location")
        region = request.form.get("region")

        # get original particulars from database
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        og_bio = rows[0]["bio"]
        og_occupation = rows[0]["occupation"]
        og_location = rows[0]["location"]
        og_region = rows[0]["region"]

        # if form is blank, set new particulars as original particulars
        if not bio and og_bio != "":
            bio = og_bio
        if not occupation and og_occupation != "":
            occupation = og_occupation
        if not location and og_location != "":
            location = og_location
        if not region and og_region != "":
            region = og_region

        # update users database
        db.execute("UPDATE users SET bio = :bio, occupation = :occupation, location = :location, region = :region WHERE username = :username",
                    bio=bio, occupation=occupation, location=location, region=region, username=username)
        return redirect("/profile")

    else:
        return render_template("editprofile.html")


# see user's own location
@app.route("/map")
@login_required
def map():

    username = session["username"]

    # get location from database
    rows = db.execute("SELECT location FROM users WHERE username = :username", username=username)
    loc = rows[0]['location']

    # get coordinates and address using google maps API
    result = googlemaps.Client(key=API_KEY).geocode(loc)
    lat = result[0]["geometry"]["location"]["lat"]
    lng = result[0]["geometry"]["location"]["lng"]
    address = result[0]["formatted_address"]

    return render_template("map.html", username=username, lat=lat, lng=lng, address=address)


# check file extension
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS










# ----------- ALREADY IMPLEMENTED ----------- #

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure confirmation matches password
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 403)

        # ensure password meets requirements
        password = request.form.get("password")
        if pwdcheck(password) == False:
            return apology("password must meet requirements", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username DOES NOT EXIST and password is correct
        if len(rows) != 0:
            return apology("username has been taken", 403)

        # add new user's credentials to database
        else:
            new_username = request.form.get("username")
            new_password_hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash, bio, occupation, location, region) VALUES (:username, :hash, :bio, :occupation, :location, :region)",
                          username=new_username, hash=new_password_hash, bio="", occupation="", location="", region="")

            # Remember which user has logged in
            rows = db.execute("SELECT * FROM users WHERE username = :username", username=new_username)
            session["user_id"] = rows[0]["id"]
            session["username"] = rows[0]["username"]

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    # user reached route via POST:
    if request.method == "POST":

        # ensure new password is submitted
        if not request.form.get("newpass"):
            return apology("must provide new password", 403)

        # Ensure confirmation matches password
        elif request.form.get("newpass") != request.form.get("newconfirmation"):
            return apology("passwords must match", 403)

        # ensure password meets requirements
        newpass = request.form.get("newpass")
        if pwdcheck(newpass) == False:
            return apology("password must meet requirements", 403)

        # generate new password hash
        newpass_hash = generate_password_hash(request.form.get("newpass"), method='pbkdf2:sha256', salt_length=8)

        # ensure new password is not the existing password
        rows = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])
        existing_hash = rows[0]["hash"]
        if existing_hash == newpass_hash:
            return apology("please enter a new password")

        # update password
        else:
            db.execute("UPDATE users SET hash = :hash WHERE id = :id", hash=newpass_hash, id=session["user_id"])
            return redirect("/")

    # user reached route via GET:
    else:
        return render_template("change.html")


def pwdcheck(password):
    # ensure password is at least 8 characters
    special_symbols = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '{', '}', '[', ']', '<', '>', '?']
    if len(password) < 8:
        return False

    # contains at least one number
    elif not any(char.isdigit for char in password):
        return False

    # contains at least one uppercase and one lowercase letter
    elif not any(char.isupper for char in password) or not any(char.islower for char in password):
        return False

    elif not any(char in special_symbols for char in password):
        return False

    else:
        return True

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
