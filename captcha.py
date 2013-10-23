from __future__ import print_function, unicode_literals

from django import forms
from django.core.exceptions import ValidationError
from django.conf import settings

import recaptcha.client.captcha

class NullTextInputWidget(forms.HiddenInput):
    def render(self, name, value, attrs=None):
        return ''

class NullCharField(forms.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['widget'] = NullTextInputWidget()
        super(NullCharField, self).__init__(*args, **kwargs)

class RecaptchaForm(forms.Form):
    recaptcha_challenge_field = NullCharField()
    recaptcha_response_field = NullCharField()
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        self.theme = kwargs.pop('theme', 'white')
        super(RecaptchaForm, self).__init__(*args, **kwargs)
        
    def render_google_js(self):
        pub_key = settings.RECAPTCHA_PUBLIC_KEY
        return '<script type="text/javascript">var RecaptchaOptions = {theme: \'' + self.theme + '\'};</script><script type="text/javascript" src="http://www.google.com/recaptcha/api/challenge?k=' + pub_key + '"></script>'
    
    def clean(self):
        cleaned_data = super(RecaptchaForm, self).clean()
        recaptcha_challenge = cleaned_data.get("recaptcha_challenge_field")
        recaptcha_response = cleaned_data.get("recaptcha_response_field")

        if recaptcha_challenge and recaptcha_response and self.request:
            priv_key = settings.RECAPTCHA_PRIVATE_KEY
            r = recaptcha.client.captcha.submit(recaptcha_challenge, recaptcha_response, priv_key, self.request.META['REMOTE_ADDR'])
            if not r.is_valid:
                if r.error_code == 'invalid-site-private-key':
                    raise forms.ValidationError("Website is not configured correctly (incorrect captcha key)")
                elif r.error_code == 'invalid-request-cookie':
                    raise forms.ValidationError("The challenge parameter of the verify script was incorrect")
                elif r.error_code == 'incorrect-captcha-sol':
                    raise forms.ValidationError("Captcha was incorrect, please try again.")
                elif r.error_code == 'captcha-timeout':
                    raise forms.ValidationError("Timeout error, please try again.")
                raise forms.ValidationError("Captcha failed (unknown error)")
        else:
            raise forms.ValidationError("Missing form values")

        return cleaned_data
