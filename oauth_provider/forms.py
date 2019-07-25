from __future__ import absolute_import

from django import forms


class AuthorizeRequestTokenForm(forms.Form):
    oauth_token = forms.CharField(widget=forms.HiddenInput)
    authorize_access = forms.BooleanField(required=False)
