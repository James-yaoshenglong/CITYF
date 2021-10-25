
import flask
import os

app = flask.Flask(__name__)

app.config['flag'] = os.environ.pop('flag')


@app.route('/src')
def index():
    return open(__file__).read()


@app.route('/', methods = ['POST'])
def shrine():
    shrine = flask.request.values.get("username")

    def safe_jinja(s):
        s = s.replace('(', '').replace(')', '')
        blacklist = ['config', 'self']
        return ''.join(['{{% set {}=None%}}'.format(c) for c in blacklist]) + s

    return flask.render_template_string(safe_jinja(shrine))

@app.route('/', methods = ['GET'])
def result():
    return  """
<form action="/" method="post">
  <input type="text" name="username"><br>
</form>
<!-- src is a common floder -->
	    """
@app.route('/robots.txt')
def res():
   return 'src/'
if __name__ == '__main__':
    app.run(debug=True)
