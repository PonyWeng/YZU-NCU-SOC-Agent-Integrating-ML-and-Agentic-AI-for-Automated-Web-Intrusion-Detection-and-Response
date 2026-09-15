SECRET_KEY='local-siem-demo-only'
DEBUG=True
ROOT_URLCONF='demo_site.urls'
ALLOWED_HOSTS=['*']
MIDDLEWARE=['demo_site.middleware.AccessLogMiddleware']
INSTALLED_APPS=[]
TEMPLATES=[{'BACKEND':'django.template.backends.django.DjangoTemplates','DIRS':[__import__('pathlib').Path(__file__).resolve().parent/'templates'],'APP_DIRS':True,'OPTIONS':{'context_processors':[]}}]
