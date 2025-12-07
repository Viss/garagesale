# GarageSale

I vibecoded this nonsense, and then took it into manual review. I spent more time making claude test this things ratelimiting, useragent and referrer guardrails than building the actual app. This thing is not designed to run forever. Need to sell some stuff? dont wanna deal with ebay or vinted? want to make life easy for buyers? got a squareup account, a paypal account, or zelle? Rad, this thing is for you.

## Heads up
- This thing expects to live in /garagesale, hung off of some domain
  - Mine lives at hax.lol/garagesale
  - If you want to change that, you'll have to muck with all the paths in the .py and the various html files in templates/

## Features

### Public Site
- Single-page vertical scrolling layout
- Image carousel with thumbnails for each listing
- Payment modal with support for PayPal, Square, and Zelle
- "Haggle" button for making an offer

### Admin Interface
- Admin area accessible by rfc1918 hosts by default, but can be switched to auth-based 
- Create, edit, mark sold, relist or delete listings
  - TODO: Hm, can't edit pics at all.  
- Plug in your various api keys
  - Square for credit cards
  - Paypal
  - Zelle just generates a QR code scannable by any banking app with zelle in
- Configure SMTP for haggle emails

## Requirements

- Python 3.7+
- Flask
- SQLite (included with Python)

## Quick Start

### 1. Install Dependencies

```bash
cd garagesale
pip install -r requirements.txt
```
this may give you grief because modern python whines, you may need to add --break-system-packages, or create a python env. your call.

### 2. Run the Application

```bash
python app.py
```

it will run and dump logs to stdout. you can house it inside of byobu or screen or tmux or something, or you can wrap it in gunicorn to daemonize it, check the example in the backend dir.

The application will:
- Create the SQLite database automatically
- Start on `http://0.0.0.0:5000`
- Be accessible from your local network, or across a vpn link or something.

if you wish to hang it underneath a real webserver (HIGHLY RECOMMENDED) there are examples of how to do that for apache and nginx in the backend dir. They should be for the most part copypasteable, depending on your existing webserver config.

### 3. Access Admin Panel

1. Navigate to `http://localhost:5000/admin`
2. Default password: `admin` (CHANGE THIS IMMEDIATELY!)
3. Go to Settings to change the admin password

**Note:** The admin panel is restricted to RFC1918 private networks (192.168.x.x, 10.x.x.x, 172.16.x.x) by default.

### Security Notes

1. **Change the default admin password immediately!**
2. **Set a secure SECRET_KEY:**
   ```bash
   export SECRET_KEY="your-random-secure-key-here"
   ```

### TODO
1. Figure out how to add/remove pics for listings
2. Figure out how to make pathing agnostic to its location so it 'just works' wherever people plunk it

