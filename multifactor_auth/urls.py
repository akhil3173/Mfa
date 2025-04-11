from django.urls import path
from . import views

urlpatterns=[
    path("",views.index,name="index"),
    path("signup",views.signup, name='signup'),
    path("login",views.login_,name='login'),
    path("home",views.home,name = 'home'),
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/', views.activate, name='activate'),
    path('send_otp', views.send_otp_email, name='send_otp_email'),
    path('verify_otp', views.verify_otp, name='verify_otp'),
    path("verify_question",views.verify_question, name ='verify_question'),
    path('process-security-question', views.reg_question, name='process_security_question'),
    path("aboutus",views.aboutus,name="aboutus"),
    path("faq",views.faq,name="faq"),
    path("terms",views.terms,name="terms"),
    path("contactus",views.contactus,name="contactus"),
    path("blogs",views.blogs,name="blogs"),
    path('item/<int:item_id>', views.products, name='product'),
    path("payment",views.payment,name="payment"),
    path('logout',views.logout_view, name='logout'),
]
