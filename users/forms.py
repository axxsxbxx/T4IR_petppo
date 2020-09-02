from django.contrib.auth import forms
from django.contrib.auth.forms import SetPasswordForm
from .models import Members
from django.contrib.auth import get_user_model
from django import forms

# 비밀번호 찾기 폼
class RecoveryPwForm(forms.Form):
    name = forms.CharField(
        widget=forms.TextInput, )
    email = forms.EmailField(
        widget=forms.EmailInput, )

    class Meta:
        fields = ['name', 'email']

    def __init__(self, *args, **kwargs):
        super(RecoveryPwForm, self).__init__(*args, **kwargs)
        self.fields['name'].label = '이름'
        self.fields['name'].widget.attrs.update({
            'class': 'form-control',
            'id': 'pw_form_name',
        })
        self.fields['email'].label = '이메일'
        self.fields['email'].widget.attrs.update({
            'class': 'form-control',
            'id': 'pw_form_id',
        })


# 비밀번호 변경 창
class CustomSetPasswordForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super(CustomSetPasswordForm, self).__init__(*args, **kwargs)
        self.fields['new_password1'].label = '새 비밀번호'
        self.fields['new_password1'].widget.attrs.update({
            'class': 'form-control',
        })
        self.fields['new_password2'].label = '새 비밀번호 확인'
        self.fields['new_password2'].widget.attrs.update({
            'class': 'form-control',
        })
