package iamecho

import (
	"net/http"

	"github.com/axis-iam/vertex-sdk-go/websession"
	"github.com/labstack/echo/v4"
)

func WebSessionHandler(service *websession.Service) echo.HandlerFunc {
	return echo.WrapHandler(service.Handler())
}

func WebSession(service *websession.Service) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var err error
			service.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				err = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return err
		}
	}
}
