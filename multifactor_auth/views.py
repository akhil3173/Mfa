from django.contrib.auth.decorators import login_required
from email.message import EmailMessage
from django.shortcuts import render,redirect
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from mfa import settings
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes,force_str
from .models import UserProfile 
from .tokens import generate_token
import random
from django.core.mail import send_mail
import requests

def reg_question(request):
    """Process the submitted security question and answer."""
    if request.method == "POST":
        user = request.user
        security_question = request.POST.get("security_question")
        security_answer = request.POST.get("security_answer")

        try:
            # Retrieve or create the user's profile
            user_profile, created = UserProfile.objects.get_or_create(user=user)
            user_profile.security_question = security_question
            user_profile.security_answer = security_answer
            user_profile.save()

            messages.success(request, "Security question and answer saved successfully.")
            return redirect("home")

        except Exception as e:
            messages.error(request, f"An error occurred: {e}")
            return redirect("process_security_question")

    return redirect("process_security_question")
def verify_question(request):
     if request.method == "POST":
        user = request.user

        try:
            user_profile = user.userprofile  # Assuming a ForeignKey relation
            security_answer = request.POST.get("security_answer")

            # Check if the provided answer matches the stored answer
            if user_profile.security_answer == security_answer:
                # Redirect the user to the home page if the answer is correct
                return redirect("home")
            else:
                # If the answer is incorrect, display an error message
                messages.error(request, "Incorrect answer to security question.")
                return redirect("verify_question")

        except UserProfile.DoesNotExist:
            # If user profile not found, display an error message
            messages.error(request, "User profile not found.")
            return redirect("login")
     else:
        user= request.user
        user_profile = user.userprofile  # Assuming a ForeignKey relation
        security_question = user_profile.security_question

        return render(request, "auth/question.html", {"security_question": security_question})

         
         


def send_otp_email(email,otp):
    """
    Function to send OTP to the user's email address.
    """
    subject = 'Verification OTP'
    message = f'Your verification OTP is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    to_list = [email]
    send_mail(subject, message, from_email, to_list)

def verify_otp(request):
    """ Verifies the OTP entered by the user. """
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')


        try:
            user_profile = request.user.userprofile  # Assuming a ForeignKey relation

            if user_profile.otp == entered_otp:
                # OTP verification successful, clear OTP
                user_profile.otp = None
                user_profile.save(update_fields=["otp"])
                messages.success(request, 'OTP verification successful!')
                return redirect('verify_question')  # Redirect to the home page after successful login
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
                return redirect('verify_otp')

        except UserProfile.DoesNotExist:
            messages.error(request, 'User profile not found.')
            return redirect('some_error_page')

    return render(request, 'auth/otp_verification_page.html')

def index(request):
    return render(request,"auth/index.html")
def home(request):
    return render(request,"auth/home.html")
def signup(request):

    if request.method == "POST":
        username = request.POST["username"]
        fname = request.POST["fname"]
        lname = request.POST["lname"]
        email = request.POST["email"]
        pass1 = request.POST["pass1"]
        pass2 = request.POST["pass2"]

        if User.objects.filter(username=username):
            messages.error(request,"Username already exist! try any other Username")
            return redirect("signup")
        
        if User.objects.filter(email=email):
            messages.error(request,"Email ID already registered!")
            return redirect("signup")
        
        if len(username)>10:
            messages.error(request,"Username must be under 10 characters")
            return redirect("signup")
        
        if len(pass1)<8:
            messages.error(request,"Password must be 8 characters or more")
        
        if pass1 != pass2:
            messages.error(request,"Passwords didn't match!!")
            return redirect("signup")
        
        if not username.isalnum():
            messages.error(request,"Username must be Alpha-Numeric!!")
            return redirect("signup")
        

        myuser= User.objects.create_user(username,email,pass1)
        UserProfile.objects.create(user=myuser)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active= False
        myuser.save()



        messages.success(request,"your account has been created successfully. we have sent you a confirmation,please confirm your email address to activate your account.")

        #welcome email
        subject ="Welcome to Casmart!"
        message ="Hello "+ myuser.first_name+" ,Welcome to Casmart, This is the Shopping website for new trends. \nWe have also sent you a confirmation email,please confirm your email address to activate your account.\n -Casmart."
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        email_1=EmailMessage(subject,message,from_email,to_list)
        email_1.send()

        #confirmation email
        current_site =get_current_site(request)
        email_subject ="Confirm your email @Casmart - Login!!"
        message2= render_to_string('email_verification.html',{
                'name': myuser.first_name,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
                'token': generate_token.make_token(myuser)
                })
        email= EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently=True
        email.send()

    return render(request,"auth/signup.html")
def activate(request,uidb64,token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode("utf-8")
        myuser= User.objects.get(pk=uid)
    except(TypeError, ValueError,OverflowError,User.DoesNotExist):
        myuser= None
    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        fname=myuser.first_name
        lname=myuser.last_name 
        return render(request,"auth/reg_question.html")
    else:
        return render(request,"verification_failed.html")

def generate_otp():
    """
    Function to generate a random six-digit OTP.
    """
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def login_(request):
    """ Handles user login and initiates OTP verification. """
    if request.user.is_authenticated:
        return redirect("home")

    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["pass1"]

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            try:
                user_profile = user.userprofile  # Assuming a ForeignKey relation

                # Generate and set OTP securely (replace with secure method)
                otp = generate_otp()
                user_profile.otp = otp
                user_profile.save(update_fields=["otp"])  # Update only OTP field

                # Send OTP via email
                send_otp_email(user.email, otp)

                messages.info(request, "An OTP has been sent to your email for verification.")
                return redirect("verify_otp")

            except UserProfile.DoesNotExist:
                messages.error(request, "User profile not found.")
                return redirect("login")

        else:
            messages.error(request, "Wrong credentials!")
            return redirect("login")

    return render(request, "auth/login.html")
def aboutus(request):
    return render(request,"auth/aboutus.html")
def faq(request):
    return render(request,"auth/faq.html")
def terms(request):
    return render(request,"auth/terms.html")
def contactus(request):
    return render(request,"auth/contactus.html")
def blogs(request):
    return render(request,"auth/blogpage.html")

def products(request ,item_id):
    if item_id== 1:
        return render(request,"auth/product-1.html")
    if item_id == 2:
        return render(request,"auth/product-2.html")
    if item_id == 3:
        return render(request,"auth/product-3.html")
    if item_id == 4:
        return render(request,"auth/product-4.html")
def payment(request):
    return render(request,"auth/payment.html")  
def logout_view(request):
    logout(request)
    return redirect("index")