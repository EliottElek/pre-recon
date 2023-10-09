# scanner/forms.py


from calendar import c
from django import forms

from home.models import Scan, Target


class TargetForm(forms.Form):
    domain_name = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500',
            'placeholder': 'Enter domain name',
        }),
    )
    description = forms.CharField(
        max_length=100,
        widget=forms.Textarea(attrs={
            'class': 'block p-2.5 mb-3 w-full text-sm text-gray-900 bg-gray-50 rounded-lg border border-gray-300 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500',
            'placeholder': 'The description for this target.',
            'required': "false"
        }),
    )


class ScanForm(forms.Form):
    target = forms.ModelChoiceField(queryset=Target.objects.all(), widget=forms.Select(attrs={
        'class': 'bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-50',
        'placeholder': 'Enter IP or Host',
    }))
    description = forms.CharField(
        max_length=100,
        widget=forms.Textarea(attrs={
            'class': 'block p-2.5 mb-3 w-full text-sm text-gray-900 bg-gray-50 rounded-lg border border-gray-300 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500',
            'placeholder': 'The description for this scan.',
        }),
    )


class DeleteScansForm(forms.Form):
    class Meta:
        model = Scan
        fields = ['ids']
