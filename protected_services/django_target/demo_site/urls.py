from django.http import JsonResponse
from django.shortcuts import render
from django.urls import path

def portal(request, notice='今日受理 126 件線上申辦'):
    query = request.GET.get('q', '')
    if query:
        notice = f'已搜尋公共服務：{query}'
    return render(request, 'portal.html', {'query': query, 'notice': notice})

def index(request): return portal(request)
def search(request): return portal(request)
def login(request): return portal(request, f'{request.GET.get("user") or "市民"}登入驗證請求已收到')
def demo_page(request): return portal(request, f'Demo 路徑：{request.path}')
def api_data(request): return JsonResponse({'service':'civic-connect','id':request.GET.get('id'),'status':'ok'})
def health(request): return JsonResponse({'service':'django-target','status':'healthy'})
def demo_error(request): return JsonResponse({'service':'django-target','status':'demo error'},status=500)

urlpatterns=[path('',index),path('search',search),path('login',login),path('product',demo_page),
             path('cart',demo_page),path('about',demo_page),path('file',demo_page),
             path('redirect',demo_page),path('api/data',api_data),path('health',health),path('demo-error',demo_error)]
