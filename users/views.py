from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import SuccessURLAllowedHostsMixin
from django.core.paginator import Paginator
from django.shortcuts import render, redirect
from django.views.generic import FormView

from reviews.models import Contents, Comments
from .models import Members
from django.shortcuts import render
from django.contrib.auth.hashers import make_password, check_password  #비밀번호 암호화
from django.core.exceptions import ObjectDoesNotExist   #이메일 중복 체크
from django.contrib.auth.models import User
from django.contrib import auth


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

            #elif not password == re_password:
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
    user = User.objects.get(username=request.user.username)
    page_r = request.GET.get('page_r', 1)
    page_c = request.GET.get('page_c', 1)
    rlist = Contents.objects.filter(nickname_id=str(user)).order_by("-id")
    clist = Comments.objects.filter(nickname_id=str(user)).order_by("-id")
    paginator_r = Paginator(rlist, 3)
    paginator_c = Paginator(clist, 6)
    rlistpage = paginator_r.get_page(page_r)
    clistpage = paginator_c.get_page(page_c)
    context = {"rlist": rlistpage, "clist":clistpage}

    return render(request, 'mypage.html', context)

def delete(request):
    id = request.GET['id']
    user = User.objects.get(username=request.user.username)
    review = Contents.objects.get(id=id)
    if str(user) == str(review.nickname_id):
        review.delete()
    return redirect("mypage")

def commentdelete(request):
    id = request.GET['id']
    user = User.objects.get(username=request.user.username)
    comment = Comments.objects.get(id=id)
    if str(user) == str(comment.nickname_id):
        comment.delete()
    return redirect("mypage")