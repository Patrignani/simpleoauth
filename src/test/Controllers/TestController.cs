using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SimpleOAuth.Models;

namespace test.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        private readonly TokenRead _token;
        public TestController(TokenRead token)
        {
            _token = token;
        }

        // GET: api/Test
        [Authorize]
        [HttpGet]
        public IActionResult Get()
        {
            var id = _token.GetValue("Id");
            return Ok(_token.Claims);
        }

        // GET: api/Test/5
        [HttpGet("{id}")]
        [Authorize(Roles ="test")]
        public IActionResult GetId(int id)
        {
            return Ok("aaa");
        }

        // POST: api/Test
        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        // PUT: api/Test/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        // DELETE: api/ApiWithActions/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
