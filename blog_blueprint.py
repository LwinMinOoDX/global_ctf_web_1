#!/usr/bin/env python3
from flask import Blueprint, request, render_template, redirect, url_for, jsonify
import requests
import os

blog_bp = Blueprint('blog', __name__, template_folder='templates/blog', static_folder='static')

# Sample blog posts
posts = [
    {
        'id': 1,
        'title': 'Welcome to Our Blog',
        'content': 'This is our first blog post. We hope you enjoy reading our content!',
        'author': 'Admin'
    },
    {
        'id': 2,
        'title': 'Web Security Basics',
        'content': 'Today we\'ll discuss some web security basics.Maybe',
        'author': 'Security Expert'
    },
    {
        'id': 3,
        'title': 'Owls quiz',
        'content': 'Are owl\'s eyes orbs or tubes?',
        'author': 'Economos'
    },
    {
        'id': 4,
        'title': 'Stupid Question?',
        'content': 'Is your favorite color teal?',
        'author': 'Some vigilante'
    },
    {
        'id': 5,
        'title': 'Bird blindness',
        'content': 'Bird blindness is real. Some people cannot tell if it\'s a duck or an eagle.',
        'author': 'Someone suffering from bird blindness'
    }
]

@blog_bp.route('/')
def home():
    return render_template('index.html', posts=posts)

@blog_bp.route('/post/<int:post_id>')
def post(post_id):
    # Find the post with the given ID
    post = next((p for p in posts if p['id'] == post_id), None)
    if not post:
        return render_template('error.html', error="Post not found"), 404
    
    # Get the previous and next post IDs for pagination
    prev_id = post_id - 1 if post_id > 1 else None
    next_id = post_id + 1 if post_id < len(posts) else None
    
    return render_template('post.html', post=post, prev_id=prev_id, next_id=next_id)

@blog_bp.route('/about')
def about():
    return render_template('about.html')

@blog_bp.route('/contact')
def contact():
    return render_template('contact.html')

@blog_bp.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "blog"})