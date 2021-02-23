using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace dotnet5_jwt_starter.Api.Authentication
{
    public class RefreshToken
    {        
        [Key]
        public string Token { get; set; }
        public string JwtId { get; set; }
        public DateTime CreatetionDate { get; set; }
        public DateTime ExpiryDate { get; set; }
        public bool Used { get; set; }
        public bool invalidated { get; set; }


        public string UserId { get; set; }

        [ForeignKey(nameof(UserId))]
        public ApplicationUser User { get; set; }
    }
}
