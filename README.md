# Plan with Authentication and Authorization


- We use a database to maintain user sessions which last a week, stored client side in a `Secure`, `HttpOnly` cookie stored in JWT format. 
- We can invalidate a session on logout at any time via the database.
- We use JWT to share the session's content with the client and verifiably authorise the client. 
- Decided against refresh tokens as that adds additional security risks as an attacker can generate sessions indefinitely, unless revoked so you end up having to maintain a list of valid sessions anyway. 
- Maintaining a list of valid sessions via database allows us to store additional information which we can pass to trusted clients and store in local storage and send with a custom header to prevent CSRF attacks. 
- An attacker would need to intercept a request via man-in-the-middle and break the SSL encryption used by HTTPS or use XSS to get access to the `csrf_token` and then do CSRF via another domain to get access to the `HttpOnly` cookie as it's not available via javascript, this is a high barrier and much less likely than a single CSRF attack. 
- I am aware this is different to the common case of JWT and JWT refresh tokens but it yields some notable security benefits while not affecting the UX that much.
 
## Content security policy 
Add a content security policy (CSP) to the site specifying 
- `script-src 'self';` disallows external scripts
- `style-src 'self';` to prevent external styles
- `img-src 'self' https://specifc-s3.url.here;` to prevent external images we do not control
- `object-src 'none';` disable object embeds
- `base-uri 'none';` do not allow base url elements to override base url
- `frame-ancestors 'none';` do not allow site to put into an iframe, prevents clickjacking
- `upgrade-insecure-requests` upgrade http requests on origin to https


 
## Authentication via login page or login endpoint

Logging in will add an `access_token` to the cookies and return this JSON:
```json
{
    "csrf_token": ...
}
```
- the `csrf_token` is stored in the client's local storage and is passed as a header with each API request
This will act as a second factor for the authentication process, so that if someone is able to steal the authentication cookie from a user they will be unable to use it without also having the addition data which is stored locally on that user's computer


### Cookie Access token
- JWT access_token is stored as a cookie with the following properties:
- `Domain=FE_URL`, with the cookies in JWT format, to be passed with future requests to API endpoints. The cookies will be sent with every request on the domain.
- `Secure` so it's only sent via HTTPS making man-in-the-middle attacks harder.
- `HttpOnly` so it's not available from JS making XSS harder
- `SameSite=strict` so cookie is only sent when the request is from the origin which issued the cookie, not from external sites making CSRF harder.



# Dev-ops 

## day 1
- Add simple email service (SES) to AWS account and get that validated first as it takes a long time to get that approved and will likely need to explain the use-case to AWS.
- Add AWS secrets manager entries for private key and public key for JWT signing
- The Lambda function's role needs to add permission to allow AWS secrets manager access.
- Add `Strict-Transport-Security` HTTP header with `includeSubdomains` set, on the cloudfront distribution and disable HTTP to HTTPS redirect see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security
- add github credentials for AWS access for terraform

## day 2-3
- create CI/CD pipeline on github actions to run the tests automatically and manage deployments via terraform if successful to deploy into a staging environment for testing.
## day 4-5
- register Domain names for the frontend, s3 file storage 
- assign domain names to cloudfront distributions of S3 and frontend
- assign lambda function to a subdomain of the frontend integrating into api gateway



# Frontend

## forms
- Use the formik react library to handle the login form and the state, validation
- Use yup schema validation library to handle form validation
- only show data validation errors after the form element has been "touched" and the user has changed focused and the element no longer passes validation.

## Day 1-2

### Function to decode JWT
- We will likely include some additional information in the JWT access token, create function to decode using standard tools,
each part of the JWT is separated by a `.` and is base64 encoded, so split on the `.` check we have 3 parts, then base64 decode the payload (the second part) and output the claims as an object.
#### unit test 
With known valid and known invalid JWTs to check it flags them correctly and processes valid correctly.

### User registration page

#### Create a form with the following fields:
- email                (input `type=email`)
- username             (input `type=text`)
- password             (input `type=password`)
- confirm password     (input `type=password`)
- TOS link to PDF    
- TOS checkbox         (input `type=checkbox`)

- See [forms](#forms) for general pointers on forms.

#### Form validation notes
- `password` should be > 10 chars, 1 capital letter, 1 lowercase letter, 1 number and 1 special char.
- `password` and `confirm password` must match
- `username` cannot be empty and is less than 20 chars
- `email` cannot be empty
- `TOS checkbox` must be checked

#### Integration tests via playright
- check all form validation rules are applied correctly

## Day 3-5
### Login page
See [general login information](#authentication-via-login-page-or-login-endpoint)

- See [forms](#forms) for general pointers on forms.
- use the input `type=password` for the password and input `type=text` for the username
- Create component for login doing API request to `/login` endpoint
- from the API response, set `csrf_token` in local storage, and pass to each future API request to authorise the client.

#### Integration test via playright
- Check known invalid input is not allowed as per validation rules and valid input passes validation
- Check whole login flow works as expected in local running environment, create a mock for emails to test the email confirmation flow

### Registration Email template

```
LOGO

Welcome to urlshortener
Please click the following link to confirm your registration

LINK
```

The LINK should go to: [Registration successful page](#registration-successful-page)


### Registration successful page

The page should submit a request to the API using the page URL's query string parameters
`POST /user/confirm?code=code-here-random-uuid`

If success response:
Offering links back to the main page of the site where you can submit links to shorten or files to upload

if not successful: (eg code already used, or other issues)
show support email and encourage them to get in touch

#### Integration tests via playright
- check that with incorrect code the logic triggers correctly


# Backend

## day1

### dynamodb tables 

#### users table
primary key on the `username`
```
username             (str)
hashed_password      (str) hashed using argon2id
email                (str)
created_at           (datetime)
last_logged_in_at    (datetime)
num_failed_logins    (int)
user_enabled         (bool)
```

#### new_user_registration table
primary key on the `registration_code`
```
username             (str)
registration_code    (str)
```

#### user_sessions table
primary key on session_id
```
session_id           (random string length > 15)
session_csrf_token   (random string length > 15)
username             (str)
created_at           (datetime)
expires_at           (datetime)
```

### create user API endpoint `POST /user`
- request body is a pydantic model with this structure

```
email                (str)         (from request)
username             (str)         (from request)
password             (str)         (from request)
```

This is then converted to a pydantic model with this structure for storage

```
email                (str)             (from request)
username             (str)             (from request)
hashed_password      (str)             hashed password from request using argon2id
created_at           (datetime)        current time
last_logged_in_at    (datetime)        None
num_failed_logins    (int)             0
user_enabled         (bool)            False
user_enabled_at      (datetime | None) None
```
We repeat some validation we did on the frontend:
- `password` should be > 10 chars, 1 capital letter, 1 lowercase letter, 1 number and 1 special char.
- `username` cannot be empty and is less than 20 chars
- `email` cannot be empty and validates with pydantic's `EmailStr`
- send registration confirmation email via AWS SES
- work with frontend team on the template see [Registration Email template](#registration-email-template)
- user is created with provided details 

return 200 on success, no need to return JSON body as frontend does not require it
return 400 on bad input

#### Integration test
- Test valid inputs are created in the database correctly
- test invalid inputs are flagged and are not added to the DB with 400 bad request

## Day 2

### Finalise user registration endpoint `POST /user/confirm?code=code-here-random-uuid`
- checks the code is the correct length say 12 chars and contains only legal chars (ascii lowercase and numbers)
- checks the code from the query parmeter matches a record in the `new_user_registration` table
- if found update the `user` with the matching `username` in the `users` table to `user_enabled=True`
- if found removes the record from `new_user_registration` table

return 200 if found
return 404 is not found

#### Integration test
- create user registration in the database and matching user table entry
- can we successfully complete this registration?
- Check that invalid registrations return 404, invalid that either the `user` OR `new_user_registration` does not exist in two tests


### login API endpoint: POST `/login`
See [general login information](#authentication-via-login-page-or-login-endpoint) for how the access_token cookie will be created

- `username` and `password` passed as form data to the backend, input into pydantic model, which disallows additional input
- Fetch matching `user` from the `users` table in the database
- if the user is not found return `HTTP 401 unauthorized`
- If the existing `num_failed_logins` for that `user` exceeds a limit of `10` return `HTTP 401 unauthorized`
- verify the stored `hashed_password` matches the provided `password` from the JSON body
else increment `num_failed_logins` for the user and return `HTTP 401 unauthorized` 
- Reset the `num_failed_logins` for the user
- We limit the number of failed attemps to mitigate against timing attacks and similar brute force approaches
- JWT token is generated see [function to create JWT](#function-to-create-JWT)
- set the JWT in the cookies see [general login information](#authentication-via-login-page-or-login-endpoint)
- return the `csrf_token` in JSON body see [general login information](#authentication-via-login-page-or-login-endpoint)

#### Integration test
- check login with good user and bad password and vise versa
- check login always fails with too many failed prior attempts (10)
- check login is successful with correct username and password
- check `csrf_token` returned matches the `user_sessions` entry for that `username` when successful


## Day 3

### function to create access_token JWT
Sign the JWT with a server side secret we obtain from `AWS secrets manager` and store into the `environment` of the running `lambda function`.
This signature's job is to check for tampering, and is done using an RSA private key. 


ensure that the following claims are set:
- iss (issuer) as the API's URL
- sub (subject) as the username
- aud (audience) as the URL of the frontend
- exp (expiry) as 1 week ahead of current time, since the database session is the primary means of security this is a token for the React FE's convenience mainly
- nbf (not before) as the current time
- iat (issued at) as the current time
- alg (algorithm) JWT signing algorithm as `RS256`
- session_id (str) non-standard field we add to check the current session has not been revoked

#### Unit test
- check creates JWTs which match known specifications for fixed input
- check JWTs can be verified correctly with matching public key

## Day 4-5

### Create `verify_authorisation` function to check JWT and csrf_token validity server side
- use RSA public key and JWT verify function to verify the signature of the JWT is valid
- check the `csrf_token` submitted via the custom header `csrf-token` matches the `user_sessions.session_csrf_token` value for that user
- note: the username is given from the `jwt.sub`
- returns `username`

### Add `verify_authorisation` as dependency to existing endpoints to restrict access to logged in users
- Use the returned `username` to perform CRUD operations on the database specific only to that user.
- Remove references to `hard_coded_user`
#### Integration Testing
- Check cannot access without being logged in having a valid JWT and csrf_token for each existing endpoint






