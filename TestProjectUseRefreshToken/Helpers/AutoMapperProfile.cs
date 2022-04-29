namespace WebApi.Helpers;

using AutoMapper;
using TestProjectUseRefreshToken.Entities;
using TestProjectUseRefreshToken.Models;

public class AutoMapperProfile : Profile
{
    // mappings between model and entity objects
    public AutoMapperProfile()
    {
        CreateMap<Account, AccountResponse>();

        CreateMap<Account, AuthenticateResponse>();

        CreateMap<RegisterRequest, Account>();

        CreateMap<CreateRequest, Account>();
    }
}