## Synopsis

Multi-User Blog built with Python.

## Code Example

blog.py handles all the main code, utilizes Jinja2 for html rendering and templates.

## Motivation

To learn and grasp techniques learnt in HTML/CSS/Python taught in my Udacity course.

## Installation

Dependencies to use code:
Python 2.7
Google App Engine
Jinja2

To Install:

1. Clone/Fork this repo locally.
2. You can use command line to run locally when testing by running dev_appserver.py.

To Deploy:

1. Download *GoogleAppEngine SDK* from Google's [site](https://cloud.google.com/appengine/ "Google App Engine").
2. Extract downloaded file and place wherever you want it kept.
3. Go to blog directory and run **gcloud init**. Follow instructions there.
4. When ready to publish use **gcloud app deploy index.yaml** to deploy your indexes first.
5. Then use **gcloud app deploy** to deploy your blog.
6. Blog can be accessed quickly using **gcloud app browse**.
7. URL will be [your-blog-id].appspot.com.

## Tests

HTML Outputs correct and usable web page with no errors.

## Demo

Compiled and final product can be seen [here](https://multi-user-blog-gm.appspot.com "Multi-User Blog")
