using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using System.Text;
using todolist.Helper;
using todolist.Models;
using Microsoft.EntityFrameworkCore.Query.Internal;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

namespace todolist.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly TodolistContext _dbcontext;

        public UserController(TodolistContext dbcontext)
        {
            _dbcontext = dbcontext;
        }










        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _dbcontext.Users.FirstOrDefaultAsync(x => x.Email == userObj.Email);

            if (user == null)
                return NotFound(new { Message = "User not found" });


            
            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {

                return BadRequest(new {Message="password is incorrect"});
            }

            user.Token=CreateJwt(user);


            return Ok(
                 new
                 {
                     Token = user.Token,


                     Message = "login success"
                 }
                ) ; 


        }




        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj) {



            userObj.Iduser = Guid.NewGuid();
            if (userObj == null)
                return BadRequest();

            //check email

            if (await CheckemailExistAsync(userObj.Email))
                return BadRequest(new { Message = "email already exixst" });

            //check password

            var passMessage = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(passMessage))
                return BadRequest(new { Message = passMessage.ToString() });


            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";




            await _dbcontext.Users.AddAsync(userObj);
            await _dbcontext.SaveChangesAsync();

            return Ok(
                 new
                 {
                     Message = "wa hahowa tzad "
                 }
                );



        }

        private Task<bool> CheckemailExistAsync(string email)
        {
            return _dbcontext.Users.AnyAsync(x => x.Email == email);

        }


        private static string CheckPasswordStrength(string pass)
        {
            StringBuilder sb = new StringBuilder();
            if (pass.Length < 9)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(pass, "[a-z]") && Regex.IsMatch(pass, "[A-Z]") && Regex.IsMatch(pass, "[0-9]")))
                sb.Append("Password should be AlphaNumeric" + Environment.NewLine);
            if (!Regex.IsMatch(pass, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special charcter" + Environment.NewLine);
            return sb.ToString();
        }


        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes("veryverysceret.....");

            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),

                new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}")


            });

            var credentias = new SigningCredentials
                (new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                /* Expires = DateTime.Now.AddDays(1),*/
                Expires = DateTime.Now.AddSeconds(10),
             
                SigningCredentials = credentias

            };

            var token=jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);
        }



        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _dbcontext.Users.ToListAsync());
        }

    }







}


