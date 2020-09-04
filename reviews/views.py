from django.core.paginator import Paginator
from django.shortcuts import render, redirect

from reviews.models import Contents, Comments


def findlocation(request):
    return render(request, "location.html")

def search1(request, location) :
    page = request.GET.get('page', 1)
    rlist = Contents.objects.filter(location = location)
    paginator = Paginator(rlist, 5)
    rlistpage = paginator.get_page(page)
    context = {"rlist": rlistpage}
    return render(request, 'search.html', context)

def search2(request, location) :
    page = request.GET.get('page', 1)
    rlist = Contents.objects.filter(location__contains = location)
    paginator = Paginator(rlist, 5)
    rlistpage = paginator.get_page(page)
    context = {"rlist": rlistpage}
    return render(request, 'search.html', context)


def searchpart(request) :
    return render(request, "location.html")


def findsymptom(request):
    symp_filter=request.GET.get('symp_filter')
    if symp_filter == "전체":
        page = request.GET.get('page', 1)
        rlist = Contents.objects.filter().order_by("-id")
        paginator = Paginator(rlist, 5)
        rlistpage = paginator.get_page(page)
        context = {"rlist": rlistpage, "symp_filter": symp_filter}
    else:
        page = request.GET.get('page', 1)
        rlist = Contents.objects.filter(symp_id=symp_filter).order_by("-id")
        paginator = Paginator(rlist, 5)
        rlistpage = paginator.get_page(page)
        context = {"rlist":rlistpage, "symp_filter": symp_filter}
    return render(request, "symptom.html", context)

def showreview(request, id):
    try:
        review = Contents.objects.get(id=id)
        context = {"review": review}
    except Contents.DoesNotExist:
        context = {"msg": "리뷰가 존재하지 않습니다."}
    return render(request, "review.html", context)

def writereview(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        location = request.POST.get('location')
        visitdate = request.POST.get('visitdate')
        writedate = request.POST.get('writedate')
        rate = request.POST.get('rate')
        content = request.POST.get('content')
        symp_id = request.POST.get('symp_id')
        recommend = 0
        receipt  = request.FILES['receipt']
        nickname_id = request.POST.get('nickname_id')
        review = Contents(location=location, content=content, title=title,
                          writedate=writedate, recommend=recommend,
                          rate=rate, visitdate=visitdate, symp_id=symp_id,
                          receipt=receipt, nickname_id=nickname_id)
        review.save()
        return redirect("/review/symptom/")
    else:
        return render(request, "write.html")


def writecomment(request):
    if request.method == 'POST':
        nickname_id = request.POST.get('nickname_id')
        commentdate = request.POST.get('commentdate')
        commenttext = request.POST.get('commenttext')
        contentsnumber_id = request.POST.get('contentsnumber_id')
        comment = Comments(nickname_id=nickname_id, commentdate=commentdate,
                           commenttext=commenttext, contentsnumber_id=contentsnumber_id)
        comment.save()
        return redirect("/review/"+contentsnumber_id+"/")


def heart(request, id):
    try:
        review = Contents.objects.get(id=id)
        review.recommend += 1
        review.save()
        return redirect("/review/"+str(id)+"/")
    except Contents.DoesNotExist:
        return redirect("/review/"+str(id)+"/")