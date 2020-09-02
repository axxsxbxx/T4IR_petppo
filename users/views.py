from django.contrib.auth import REDIRECT_FIELD_NAME, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import SuccessURLAllowedHostsMixin
from django.core.paginator import Paginator
from django.shortcuts import render, redirect
from django.views.generic import FormView
from django.views.generic.base import View

from reviews.models import Contents
from .models import Members
from django.shortcuts import render
from django.contrib.auth.hashers import make_password, check_password  #비밀번호 암호화
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied  # 이메일 중복 체크
from django.contrib.auth.models import User
from django.contrib import auth, messages

#비밀번호 찾기
from django.utils.decorators import method_decorator
#from .decorators import login_message_required, admin_required, logout_message_required
from .forms import RecoveryPwForm
from .helper import send_mail, email_auth_num
from django.http import HttpResponse
import json
from django.core.serializers.json import DjangoJSONEncoder
from django.template.loader import render_to_string
from .forms import CustomSetPasswordForm


def petppologin(request):
    return render(request, "login.html")

#def makeanewid(request):
#    return render(request, "signup.html")

class LoginView(SuccessURLAllowedHostsMixin, FormView):
    """
    Display the login form and handle the login action.
    """
    form_class = AuthenticationForm
    authentication_form = None
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = 'registration/login.html'
    redirect_authenticated_user = False
    extra_context = None





def register(request):
    results = {}

    if request.method == 'GET':
        return render(request, 'signup.html', results)

    elif request.method == 'POST':
        email = request.POST.get('email', None)
        name = request.POST.get('name', None)
        password = request.POST.get('password', None)
        #re_password = request.POST.get('re-password', None)
        nickname = request.POST.get('nickname', None)
        addr_id = request.POST.get('addr_id', None)
        kind = request.POST.get('kind', None)
        petage = request.POST.get('petage', None)
        petgender = request.POST.get('petgender', None)

        try:    #이메일 중복체크
            asked_user = Members.objects.get(email=email)
            results['error'] = asked_user.email + ' : 사용중인 이메일입니다.'
            return render(request, 'signup.html', results)
        except ObjectDoesNotExist:
            pass

        if not (email and name and password ):        #and re_password
            results['error'] = '모든 값을 입력하시오.'

        else:
            if len(name) > 20:
                results['error'] = '이름은 최대 5글자입니다.'
            elif len(nickname) > 20:
                results['error'] = '닉네임은 최대 10글자입니다.'
            elif len(password) > 20:
                results['error'] = '비밀번호는 최대 12글자입니다.'

            #elif not password == re-password:
            #    results['error'] = '비밀번호가 일치하지 않습니다.'

            else:   #입력값 DB에 등록.    #장고에서 제공하는 비밀번호 암호화/복호화
                new_user = Members(email=email, name=name, password=make_password( str(password)),
                                   nickname=nickname, addr_id=addr_id, kind=kind, petage=petage, petgender=petgender,
                                    )
                new_user.save()
                user = User.objects.create_user(username=request.POST['email'], password=request.POST['password'])
                auth.login(request, user)
                results['error'] = '정상적으로 가입되었습니다.'

        return render(request, 'signup.html', results)

def myreview(request):
    petppoid = request.POST.get('petppoid')
    page = request.GET.get('page', 1)
    rlist = Contents.objects.filter(nickname_id=petppoid).order_by("-id")
    paginator = Paginator(rlist, 5)
    rlistpage = paginator.get_page(page)
    context = {"rlist": rlistpage}

    return render(request, 'mypage.html', context)






# 비밀번호찾기
#@method_decorator(logout_message_required, name='dispatch')
class RecoveryPwView(View):
    template_name = 'users/recovery_pw.html'
    recovery_pw = RecoveryPwForm

    def get(self, request):
        if request.method=='GET':
            form_pw = self.recovery_pw(None)
            return render(request, self.template_name, { 'form_pw':form_pw, })


def ajax_find_pw_view(request):
    #user_id = request.POST.get('user_id')
    name = request.POST.get('name')
    email = request.POST.get('email')
    result_pw = User.objects.get(name=name, email=email)    #user_id=user_id,

    if result_pw:
        auth_num = email_auth_num()
        result_pw.auth = auth_num
        result_pw.save()

        send_mail(
            '[RE:PASSWORD] 비밀번호 찾기 인증메일입니다.',
            [email],
            html=render_to_string('users/recovery_email.html', {
                'auth_num': auth_num,
            }),
        )
    # print(auth_num)
    return HttpResponse(json.dumps({"result": result_pw.user_id}, cls=DjangoJSONEncoder), content_type = "application/json")


def auth_confirm_view(request):
    # if request.method=='POST' and 'auth_confirm' in request.POST:
    email = request.POST.get('email')
    input_auth_num = request.POST.get('input_auth_num')
    user = User.objects.get(email=email, auth=input_auth_num)
    # login(request, user)
    user.auth = ""
    user.save()
    request.session['auth'] = user.email

    return HttpResponse(json.dumps({"result": user.email}, cls=DjangoJSONEncoder), content_type="application/json")

#@logout_message_required
def auth_pw_reset_view(request):
    if request.method == 'GET':
        if not request.session.get('auth', False):
            raise PermissionDenied

    if request.method == 'POST':
        session_user = request.session['auth']
        current_user = User.objects.get(user_id=session_user)
        # del(request.session['auth'])
        login(request, current_user)

        reset_password_form = CustomSetPasswordForm(request.user, request.POST)

        if reset_password_form.is_valid():
            user = reset_password_form.save()
            messages.success(request, "비밀번호 변경완료! 변경된 비밀번호로 로그인하세요.")
            logout(request)
            return redirect('users:login')
        else:
            logout(request)
            request.session['auth'] = session_user
    else:
        reset_password_form = CustomSetPasswordForm(request.user)

    return render(request, 'users/password_reset.html', {'form': reset_password_form})